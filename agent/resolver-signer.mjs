#!/usr/bin/env node
// Independent resolver signer. A signer authorizes a quorum decision only
// after its own sandbox transcript agrees with the published transcript and
// two RPC providers agree on the finalized chain state.

import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ethers } from "ethers";

import { manifestProblemContracts, manifestProblemForRegistryId, validateManifestEvidence } from "./indexer.mjs";
import { canonicalJson, resolveOperatorFinality } from "./lib.mjs";
import { loadProductionValidationContext } from "./production-validation-context.mjs";
import {
  buildResolverVerdictHash,
  verifyLiveRegistryBinding,
  verifyResolverTranscript,
} from "./resolver.mjs";
import {
  buildResolverQuorumSignatureArtifact,
  deterministicResolverNonce,
  validateResolverQuorumDecisionPacket,
} from "./resolver-quorum.mjs";
import {
  canonicalTranscriptArtifact,
  configuredTranscriptEndpoints,
  fetchTranscriptClientBytes,
  httpTranscriptFetchClient,
  parseTranscriptUri,
  verifyPublicationReceipt,
} from "./transcript-store.mjs";
import {
  parseStrictJsonBytes,
  readStrictJsonFileSync,
  writeTrustedFileExclusiveSync,
  writeTrustedFileSync,
} from "./strict-json.mjs";

const JSON_LIMITS = Object.freeze({ maxBytes: 16 * 1024 * 1024, maxDepth: 64, canonicalBytes: true, trailingNewline: "require" });
const SIGNER_ABIS = Object.freeze({
  P42SubmissionManager: Object.freeze([
    "function revealInstanceHashOf(uint256) view returns (bytes32)",
    "function submissions(uint256) view returns (address solver, bytes32 commitment, bytes32 commitDaHash, uint256 bondWei, uint256 poolAtSubmissionWei, uint256 requiredBondWei, uint256 improvementAtoms, int256 claimedScoreAtoms, string solutionCid, bytes32 permanenceHash, uint64 committedAt, uint64 revealedAt, uint64 challengeEndsAt, uint8 status)",
  ]),
  P42ChallengeManager: Object.freeze([
    "function challengeInstanceHashOf(uint256) view returns (bytes32)",
    "function challengeRevealInstanceHashOf(uint256) view returns (bytes32)",
    "function challenges(uint256) view returns (uint256 submissionId, address challenger, bytes32 reasonHash, uint256 challengeBondWei, uint64 challengedAt, uint64 disputeEndsAt, bool resolved, bool decisionPending, bool challengerWins, bytes32 transcriptHash, string transcriptURI, bytes32 verdictHash)",
    "function resolver() view returns (address)",
    "function resolverDecisionBondWei() view returns (uint256)",
  ]),
  P42ProblemRegistry: Object.freeze([
    "function explicitlyFrozen(uint256 problemId) view returns (bool)",
    "function isFrozen(uint256 problemId) view returns (bool)",
    "function problems(uint256) view returns (bytes32 specHash, bytes32 verifierSourceHash, bytes32 verifierImageHash, bytes32 admissionMatrixHash, string metadataURI, address pool, address ledger, address submissionManager, address challengeManager, uint64 challengeWindowSeconds, uint256 minImprovementAtoms, bool frozen)",
  ]),
  P42ResolverQuorum: Object.freeze([
    "function epochThreshold(uint64) view returns (uint256)",
    "function isEpochSigner(uint64 epoch, address signer) view returns (bool)",
    "function isManager(address) view returns (bool)",
    "function nonceUsed(address,uint256) view returns (bool)",
    "function paused() view returns (bool)",
    "function signerEpoch() view returns (uint64)",
  ]),
});

function arg(argv, name, defaultValue = undefined) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1) return defaultValue;
  const value = argv[index + 1];
  return value && !value.startsWith("--") ? value : true;
}

function repeatedArgs(argv, name) {
  const values = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === `--${name}` && argv[index + 1] && !argv[index + 1].startsWith("--")) {
      values.push(argv[index + 1]);
    }
  }
  return values;
}

function sameAddress(left, right) {
  return ethers.isAddress(left) && ethers.isAddress(right)
    && ethers.getAddress(left).toLowerCase() === ethers.getAddress(right).toLowerCase();
}

function sameBytes32(left, right) {
  return ethers.isHexString(left, 32) && ethers.isHexString(right, 32)
    && String(left).toLowerCase() === String(right).toLowerCase();
}

function requireEqual(left, right, message) {
  if (canonicalJson(left) !== canonicalJson(right)) throw new Error(message);
}

function verifyIndependentDaEvidence(published, local) {
  const left = published.transcript.da;
  const right = local.transcript.da;
  if (!left || !right || typeof left !== "object" || typeof right !== "object"
      || typeof left.ok !== "boolean" || typeof right.ok !== "boolean" || left.ok !== right.ok) {
    throw new Error("independent rerun DA outcome does not match the published transcript");
  }
  if (left.ok) {
    for (const field of ["expected_hash", "observed_hash"]) {
      if (!/^sha256:[0-9a-f]{64}$/.test(String(left[field])) || left[field] !== right[field]) {
        throw new Error(`independent rerun DA ${field} does not match the committed payload`);
      }
    }
    if (left.expected_hash !== left.observed_hash
        || published.report?.solution_hash !== left.expected_hash
        || local.report?.solution_hash !== right.expected_hash) {
      throw new Error("verifier solution hash does not match the independently retrieved committed payload");
    }
    return;
  }
  for (const field of ["mode", "expected_hash", "failure_kind", "challengeable", "retryable"]) {
    if (left[field] !== right[field]) {
      throw new Error(`independent rerun DA failure field ${field} does not match the published transcript`);
    }
  }
  if (left.challengeable !== true || left.retryable === true) {
    throw new Error("resolver signer refuses unavailable or non-challengeable DA evidence");
  }
}

function expectedTranscriptBinding(packet, registryAddress, registryProblemId, problemSlug) {
  return {
    chain_id: Number(packet.decision.chainId),
    problem_id: problemSlug,
    submission_contract: packet.decision.manager,
    challenge_contract: packet.decision.manager,
    submission_id: packet.decision.submissionId,
    registry_address: registryAddress,
    registry_problem_id: String(registryProblemId),
    registry_problem_slug: problemSlug,
  };
}

export function verifyIndependentResolverDecision({
  packet: packetValue,
  publishedTranscript,
  localTranscript,
  registryAddress,
  registryProblemId,
  problemSlug,
  live,
}) {
  const packet = validateResolverQuorumDecisionPacket(packetValue);
  const expected = expectedTranscriptBinding(
    packet,
    ethers.getAddress(registryAddress).toLowerCase(),
    registryProblemId,
    problemSlug,
  );
  // The manager in the decision is the challenge manager. The submission
  // manager comes from the transcript's frozen registry binding, so replace
  // that expected field before validation instead of trusting the packet.
  delete expected.submission_contract;
  const published = verifyResolverTranscript(publishedTranscript, expected);
  const local = verifyResolverTranscript(localTranscript, {
    ...expected,
    submission_contract: published.claim.submission_contract,
    reveal_instance_hash: published.claim.reveal_instance_hash,
  });

  if (!sameBytes32(packet.decision.transcriptHash, published.transcriptHashBytes32)) {
    throw new Error("resolver packet transcript hash does not match the published transcript");
  }
  if (packet.decision.nonce !== deterministicResolverNonce(packet.decision.challengeInstanceHash)) {
    throw new Error("resolver packet nonce is not the deterministic challenge nonce");
  }
  if (!sameAddress(packet.decision.manager, published.claim.challenge_contract)) {
    throw new Error("resolver packet manager does not match the transcript challenge manager");
  }
  if (packet.decision.submissionId !== published.claim.submission_id) {
    throw new Error("resolver packet submission does not match the transcript");
  }
  if (packet.decision.expiry !== published.claim.challenge_ends_at) {
    throw new Error("resolver packet expiry does not match the challenge deadline");
  }
  if (Boolean(packet.decision.challengerWins) !== published.challengerWins) {
    throw new Error("resolver packet outcome does not match the published verifier decision");
  }
  requireEqual(local.claim, published.claim, "independent rerun chain claim does not match the published transcript");
  requireEqual(
    local.transcript.verifier.chain_claim,
    published.transcript.verifier.chain_claim,
    "independent rerun full chain claim does not match the published transcript",
  );
  requireEqual(local.registryBinding, published.registryBinding, "independent rerun registry binding does not match the published transcript");
  requireEqual(local.candidate, published.candidate, "independent rerun candidate does not match the published transcript");
  requireEqual(local.report, published.report, "independent rerun VerdictReport does not match the published transcript");
  if (local.challengerWins !== published.challengerWins) {
    throw new Error("independent rerun outcome does not match the published transcript");
  }
  verifyIndependentDaEvidence(published, local);

  const verdictHash = buildResolverVerdictHash({
    transcriptHash: published.transcript.transcript_hash,
    candidateHash: published.candidate.candidate_hash,
    challengerWins: published.challengerWins,
    revealInstanceHash: published.claim.reveal_instance_hash,
    challengeInstanceHash: packet.decision.challengeInstanceHash,
  });
  if (!sameBytes32(packet.decision.verdictHash, verdictHash)) {
    throw new Error("resolver packet verdict hash does not bind the independently checked evidence");
  }
  if (!sameAddress(packet.decision.adapter, live.quorum)
      || !sameAddress(packet.decision.bondBeneficiary, live.quorum)) {
    throw new Error("resolver packet adapter or bond beneficiary does not match the live quorum");
  }
  if (!sameAddress(live.manager, packet.decision.manager)
      || !sameAddress(live.managerResolver, live.quorum)) {
    throw new Error("live challenge manager resolver binding is not canonical");
  }
  if (String(live.submissionId) !== packet.decision.submissionId
      || String(live.challengeSubmissionId) !== packet.decision.submissionId
      || String(live.submissionStatus) !== "3") {
    throw new Error("live submission is not the challenged submission");
  }
  if (!sameBytes32(live.revealInstanceHash, published.claim.reveal_instance_hash)
      || !sameBytes32(live.challengeRevealInstanceHash, published.claim.reveal_instance_hash)
      || !sameBytes32(live.challengeInstanceHash, packet.decision.challengeInstanceHash)) {
    throw new Error("live challenge instance does not match the signed evidence");
  }
  if (String(live.disputeEndsAt) !== packet.decision.expiry
      || BigInt(live.finalizedTimestamp) >= BigInt(packet.decision.expiry)) {
    throw new Error("resolver packet is expired or its live dispute deadline changed");
  }
  if (live.resolved || live.decisionPending || live.quorumPaused || !live.isManager || live.nonceUsed) {
    throw new Error("live challenge or quorum state is not signable");
  }
  if (String(live.signerEpoch) !== packet.decision.signerEpoch || BigInt(live.threshold) < 1n) {
    throw new Error("resolver signer epoch or threshold changed");
  }
  if (BigInt(live.resolverDecisionBondWei) < 1n
      || BigInt(live.quorumBalanceWei) < BigInt(live.resolverDecisionBondWei)) {
    throw new Error("resolver quorum stake cannot cover the live decision bond");
  }
  parseTranscriptUri(packet.transcript_uri);
  return { packet, published, local, verdictHash };
}

function normalizeSnapshot(value) {
  return JSON.parse(JSON.stringify(value, (_key, item) => typeof item === "bigint" ? item.toString() : item));
}

async function finalizedAgreement(primary, secondary) {
  const [leftFinalized, rightFinalized] = await Promise.all([
    primary.getBlock("finalized"),
    secondary.getBlock("finalized"),
  ]);
  if (!leftFinalized || !rightFinalized) throw new Error("both RPCs must expose a finalized block");
  const blockNumber = Math.min(leftFinalized.number, rightFinalized.number);
  const [left, right] = await Promise.all([primary.getBlock(blockNumber), secondary.getBlock(blockNumber)]);
  if (!left?.hash || !right?.hash || !sameBytes32(left.hash, right.hash) || left.timestamp !== right.timestamp) {
    throw new Error(`configured RPCs disagree on finalized block ${blockNumber}`);
  }
  return { blockNumber, blockHash: left.hash.toLowerCase(), timestamp: left.timestamp };
}

async function observeAt(provider, contracts, packet, finalized, signerAddress) {
  const submissionId = BigInt(packet.decision.submissionId);
  const epoch = BigInt(packet.decision.signerEpoch);
  const options = { blockTag: finalized.blockNumber };
  const [submission, challenge, liveReveal, challengeReveal, challengeInstance, managerResolver,
    paused, isManager, liveEpoch, threshold, signerMember, nonceUsed, resolverDecisionBondWei,
    quorumBalanceWei] = await Promise.all([
    contracts.submissions.submissions(submissionId, options),
    contracts.challenges.challenges(submissionId, options),
    contracts.submissions.revealInstanceHashOf(submissionId, options),
    contracts.challenges.challengeRevealInstanceHashOf(submissionId, options),
    contracts.challenges.challengeInstanceHashOf(submissionId, options),
    contracts.challenges.resolver(options),
    contracts.quorum.paused(options),
    contracts.quorum.isManager(packet.decision.manager, options),
    contracts.quorum.signerEpoch(options),
    contracts.quorum.epochThreshold(epoch, options),
    signerAddress
      ? contracts.quorum.isEpochSigner(epoch, signerAddress, options)
      : Promise.resolve(null),
    contracts.quorum.nonceUsed(packet.decision.manager, packet.decision.nonce, options),
    contracts.challenges.resolverDecisionBondWei(options),
    provider.getBalance(contracts.quorum.target, finalized.blockNumber),
  ]);
  return normalizeSnapshot({
    finalizedBlockNumber: finalized.blockNumber,
    finalizedBlockHash: finalized.blockHash,
    finalizedTimestamp: finalized.timestamp,
    quorum: String(contracts.quorum.target).toLowerCase(),
    manager: String(contracts.challenges.target).toLowerCase(),
    managerResolver: String(managerResolver).toLowerCase(),
    submissionId: submissionId.toString(),
    challengeSubmissionId: challenge.submissionId,
    submissionStatus: submission.status,
    revealInstanceHash: String(liveReveal).toLowerCase(),
    challengeRevealInstanceHash: String(challengeReveal).toLowerCase(),
    challengeInstanceHash: String(challengeInstance).toLowerCase(),
    disputeEndsAt: challenge.disputeEndsAt,
    resolved: challenge.resolved,
    decisionPending: challenge.decisionPending,
    quorumPaused: paused,
    isManager,
    signerEpoch: liveEpoch,
    threshold,
    signerMember,
    nonceUsed,
    resolverDecisionBondWei,
    quorumBalanceWei,
  });
}

export async function observeIndependentSignerState({ primary, secondary, contractsFor, packet, signerAddress }) {
  const finalized = await finalizedAgreement(primary, secondary);
  const [left, right] = await Promise.all([
    observeAt(primary, contractsFor(primary), packet, finalized, signerAddress),
    observeAt(secondary, contractsFor(secondary), packet, finalized, signerAddress),
  ]);
  requireEqual(left, right, "configured RPCs disagree on finalized resolver state");
  if (signerAddress && left.signerMember !== true) throw new Error("configured signer is not a member of the packet epoch");
  return left;
}

async function fetchPublishedTranscript(packet, endpoints, fetchClient) {
  const parsed = parseTranscriptUri(packet.transcript_uri);
  const first = await fetchTranscriptClientBytes(fetchClient, { endpoint: endpoints[0], uri: parsed.uri });
  const transcript = parseStrictJsonBytes(first, JSON_LIMITS);
  const artifact = canonicalTranscriptArtifact(transcript);
  await verifyPublicationReceipt({
    artifact,
    receipt: { uri: parsed.uri, artifact_sha256: artifact.artifact_sha256, length: artifact.length },
    endpoints,
    fetchClient,
  });
  return transcript;
}

export function resolverSignerAbi(name) {
  const value = SIGNER_ABIS[name];
  if (!value) throw new Error(`resolver signer ABI is not packaged: ${name}`);
  return value;
}

function contractsForManifest(provider, manifest, problem) {
  const board = manifestProblemContracts(manifest, problem);
  return {
    submissions: new ethers.Contract(board.submissions.address, resolverSignerAbi("P42SubmissionManager"), provider),
    challenges: new ethers.Contract(board.challenges.address, resolverSignerAbi("P42ChallengeManager"), provider),
    registry: new ethers.Contract(manifest.contracts.registry.address, resolverSignerAbi("P42ProblemRegistry"), provider),
    quorum: new ethers.Contract(manifest.contracts.resolverQuorum.address, resolverSignerAbi("P42ResolverQuorum"), provider),
  };
}

function assertPrivateRoot(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid !== process.getuid() || (metadata.mode & 0o077) !== 0) {
    throw new Error("signature root must be an owner-only, non-symlink directory");
  }
}

export function signerAuthorizationPath(signatureRoot, packet) {
  const identity = [
    packet.decision.chainId,
    packet.decision.adapter.slice(2).toLowerCase(),
    packet.decision.manager.slice(2).toLowerCase(),
    packet.decision.challengeInstanceHash.slice(2).toLowerCase(),
  ].join("-");
  return join(signatureRoot, "authorizations", `${identity}.json`);
}

export function persistSignerAuthorization(signatureRoot, packet, evidence) {
  const authorizations = join(signatureRoot, "authorizations");
  assertPrivateRoot(authorizations);
  const path = signerAuthorizationPath(signatureRoot, packet);
  const semanticAuthorization = {
    schema_version: "p42-resolver-signer-authorization/v1",
    chain_id: packet.decision.chainId,
    adapter: packet.decision.adapter,
    manager: packet.decision.manager,
    challenge_instance_hash: packet.decision.challengeInstanceHash,
    decision_digest: packet.decision_digest,
    packet_hash: packet.packet_hash,
    transcript_hash: packet.decision.transcriptHash,
    transcript_uri_hash: packet.decision.transcriptURIHash,
    verdict_hash: packet.decision.verdictHash,
    challenger_wins: packet.decision.challengerWins,
    signer_epoch: packet.decision.signerEpoch,
  };
  const authorization = {
    ...semanticAuthorization,
    finalized_block_number: String(evidence.finalizedBlockNumber),
    finalized_block_hash: evidence.finalizedBlockHash,
  };
  const payload = `${canonicalJson(authorization)}\n`;
  if (!writeTrustedFileExclusiveSync(path, signatureRoot, payload)) {
    const existing = readStrictJsonFileSync(path, {
      maxBytes: 64 * 1024, maxDepth: 16, canonicalBytes: true, trailingNewline: "require",
      privateFile: true,
    });
    const existingSemantic = Object.fromEntries(Object.keys(semanticAuthorization).map((key) => [key, existing[key]]));
    if (canonicalJson(existingSemantic) !== canonicalJson(semanticAuthorization)) {
      throw new Error("anti-equivocation journal already authorizes different decision content");
    }
  }
  return path;
}

export async function main(argv = process.argv.slice(2), clients = {}) {
  const manifestPath = arg(argv, "manifest");
  const registryProblemId = arg(argv, "registry-problem-id");
  const packetPath = arg(argv, "packet");
  const localTranscriptPath = arg(argv, "local-transcript");
  const signatureRoot = resolve(arg(argv, "signature-root", ""));
  const rpcUrls = repeatedArgs(argv, "rpc");
  if (!manifestPath || !registryProblemId || !packetPath || !localTranscriptPath || !arg(argv, "signature-root")) {
    throw new Error("required: --manifest --registry-problem-id --packet --local-transcript --signature-root");
  }
  if (!clients.providers && rpcUrls.length !== 2) throw new Error("exactly two independently operated --rpc URLs are required");
  const [primary, secondary] = clients.providers ?? rpcUrls.map((url) => new ethers.JsonRpcProvider(url));
  if (primary === secondary || (rpcUrls.length === 2 && rpcUrls[0] === rpcUrls[1])) {
    throw new Error("resolver signer RPC providers must be independent");
  }
  const manifest = readStrictJsonFileSync(resolve(manifestPath), { maxBytes: 8 * 1024 * 1024, maxDepth: 96 });
  if (manifest.releaseMode !== "production") throw new Error("independent resolver signer requires a production release manifest");
  const [primaryNetwork, secondaryNetwork] = await Promise.all([primary.getNetwork(), secondary.getNetwork()]);
  const manifestChainId = BigInt(manifest.network?.chainId ?? 0);
  if (primaryNetwork.chainId !== manifestChainId || secondaryNetwork.chainId !== manifestChainId) {
    throw new Error("both resolver signer RPCs must match the manifest chain id");
  }
  validateManifestEvidence(manifest, await loadProductionValidationContext(manifest, { provider: primary, secondaryProvider: secondary }));
  resolveOperatorFinality({ manifest, localTest: false });
  const problem = manifestProblemForRegistryId(manifest, registryProblemId);
  const packet = validateResolverQuorumDecisionPacket(readStrictJsonFileSync(resolve(packetPath), JSON_LIMITS));
  const localTranscript = readStrictJsonFileSync(resolve(localTranscriptPath), { ...JSON_LIMITS, privateFile: true });
  const endpoints = clients.endpoints ?? configuredTranscriptEndpoints(argv, process.env);
  const publishedTranscript = await fetchPublishedTranscript(packet, endpoints, clients.fetchClient ?? httpTranscriptFetchClient());

  const contractsFor = (provider) => contractsForManifest(provider, manifest, problem);
  let live = await observeIndependentSignerState({
    primary, secondary, contractsFor, packet, signerAddress: null,
  });
  for (const provider of [primary, secondary]) {
    const contracts = contractsFor(provider);
    await verifyLiveRegistryBinding({
      manifest,
      provider,
      registry: contracts.registry,
      chainId: Number(manifest.network.chainId),
      registryProblemId: String(registryProblemId),
      manifestProblem: problem,
      startBlock: Number(manifest.indexer.startBlock),
      finalityConfirmations: Number(manifest.indexer.finalityPolicy.confirmations),
    }, publishedTranscript.verifier.chain_claim.registry_binding);
  }
  verifyIndependentResolverDecision({
    packet, publishedTranscript, localTranscript,
    registryAddress: manifest.contracts.registry.address,
    registryProblemId,
    problemSlug: problem.problemSlug,
    live,
  });

  // Close epoch/challenge/reorg TOCTOU after the potentially slow transcript,
  // registry, and verifier checks. A later finalized anchor is acceptable only
  // if the complete signable state remains valid at that anchor.
  const privateKey = process.env.P42_RESOLVER_SIGNER_PRIVATE_KEY;
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(privateKey))) {
    throw new Error("P42_RESOLVER_SIGNER_PRIVATE_KEY must contain exactly one private key");
  }
  const signer = new ethers.Wallet(privateKey);
  assertPrivateRoot(signatureRoot);
  assertPrivateRoot(join(signatureRoot, "authorizations"));
  live = await observeIndependentSignerState({
    primary, secondary, contractsFor, packet, signerAddress: signer.address,
  });
  verifyIndependentResolverDecision({
    packet, publishedTranscript, localTranscript,
    registryAddress: manifest.contracts.registry.address,
    registryProblemId,
    problemSlug: problem.problemSlug,
    live,
  });
  // The atomic no-clobber journal is the signing fence. Conflicting concurrent
  // processes cannot both pass it; an identical retry is harmless and remains
  // recoverable after a crash between authorization and key invocation.
  const authorizationPath = persistSignerAuthorization(signatureRoot, packet, live);
  const artifact = await buildResolverQuorumSignatureArtifact(packet, signer);
  const decisionRoot = join(signatureRoot, packet.decision_digest.slice(2));
  assertPrivateRoot(decisionRoot);
  const output = join(decisionRoot, `${artifact.signer}.json`);
  const payload = `${canonicalJson(artifact)}\n`;
  if (existsSync(output)) {
    if (readFileSync(output, "utf8") !== payload) throw new Error("refusing to overwrite a conflicting signer artifact");
  } else {
    writeTrustedFileSync(output, signatureRoot, payload);
  }
  console.log(canonicalJson({ status: "signed", signer: artifact.signer, decision_digest: packet.decision_digest, authorization: authorizationPath, output }));
  for (const provider of [primary, secondary]) provider.destroy?.();
}

const invokedPath = process.argv[1] ? pathToFileURL(realpathSync(resolve(process.argv[1]))).href : null;
if (invokedPath === import.meta.url) {
  main().catch((error) => {
    console.error("FAILED:", error.shortMessage || error.message);
    process.exitCode = 1;
  });
}
