#!/usr/bin/env node
// P42 autonomous resolver: finalized challenge -> canonical runner transcript
// -> exact, bonded resolve() call. The resolver intentionally has no authority
// to invent a verdict: a self-hashed Docker transcript must bind every decision.

import { ethers } from "ethers";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  buildSignedTransactionRecord,
  canonicalJson,
  classifyReceiptFinality,
  exactCallRequestFromPolicy,
  queryChunked,
  resolveOperatorFinality,
  sha256Canonical,
  validateOperatorExecutionMode,
} from "./lib.mjs";
import { validateManifestEvidence } from "./indexer.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHA256_RE = /^sha256:[a-f0-9]{64}$/;
const RATIONAL_RE = /^-?[0-9]+\/[1-9][0-9]*$/;
const DECIMAL_RE = /^(0|[1-9][0-9]*)$/;
const INTEGER_RE = /^-?(0|[1-9][0-9]*)$/;
const MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024;
const TERMINAL_ACTIONS = new Set([
  "confirmed",
  "broadcast_reverted",
  "superseded",
  "onchain_observed",
  "resolved_elsewhere",
  "orphaned_reorg",
]);

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requireString(value, label) {
  if (typeof value !== "string" || !value) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function normalizedAddress(value, label) {
  if (!ethers.isAddress(value)) throw new Error(`${label} must be an EVM address`);
  return ethers.getAddress(value).toLowerCase();
}

function normalizedBytes32(value, label, { allowZero = false } = {}) {
  if (!ethers.isHexString(value, 32)) throw new Error(`${label} must be 32-byte hex`);
  const normalized = String(value).toLowerCase();
  if (!allowZero && normalized === ethers.ZeroHash) throw new Error(`${label} must not be zero`);
  return normalized;
}

function requireExactKeys(value, keys, label) {
  const object = requireObject(value, label);
  const expected = new Set(keys);
  const missing = keys.filter((key) => !(key in object));
  const extra = Object.keys(object).filter((key) => !expected.has(key));
  if (missing.length || extra.length) {
    throw new Error(`${label} keys mismatch (missing: ${missing.join(",") || "none"}; extra: ${extra.join(",") || "none"})`);
  }
  return object;
}

function sha256ToBytes32(value, label) {
  if (!SHA256_RE.test(String(value))) throw new Error(`${label} must be sha256:<64 lowercase hex>`);
  return `0x${String(value).slice(7)}`;
}

function asNonnegativeDecimal(value, label) {
  const text = requireString(value, label);
  if (!DECIMAL_RE.test(text)) throw new Error(`${label} must be a non-negative canonical integer string`);
  return text;
}

function asInteger(value, label) {
  const text = requireString(value, label);
  if (!INTEGER_RE.test(text)) throw new Error(`${label} must be a canonical integer string`);
  return text;
}

function nonzeroSubmissionId(value, label) {
  const text = asNonnegativeDecimal(value, label);
  if (BigInt(text) === 0n) throw new Error(`${label} must be greater than zero`);
  return text;
}

function sameAddress(left, right) {
  return String(left).toLowerCase() === String(right).toLowerCase();
}

function sameBytes32(left, right) {
  return String(left).toLowerCase() === String(right).toLowerCase();
}

function arg(argv, name, defaultValue = undefined) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1) return defaultValue;
  const value = argv[index + 1];
  return value && !value.startsWith("--") ? value : true;
}

function sleep(ms) {
  return new Promise((done) => setTimeout(done, ms));
}

export function validateTranscriptUriTemplate(value) {
  const template = requireString(value, "--transcript-uri-template");
  if ((template.match(/\{transcript_hash\}/g) ?? []).length !== 1) {
    throw new Error("--transcript-uri-template must contain exactly one {transcript_hash} placeholder");
  }
  if (/\s/.test(template) || !/^(ar|ipfs):\/\//.test(template)) {
    throw new Error("--transcript-uri-template must be an ar:// or ipfs:// durable URI template");
  }
  if (/^file:/i.test(template) || template.includes("..")) {
    throw new Error("--transcript-uri-template must not name a file or traversal path");
  }
  return template;
}

export function expandTranscriptUri(template, transcriptHash) {
  const checked = validateTranscriptUriTemplate(template);
  if (!SHA256_RE.test(String(transcriptHash))) {
    throw new Error("transcript hash must be sha256:<64 lowercase hex>");
  }
  const uri = checked.replace("{transcript_hash}", transcriptHash);
  if (uri.includes("{") || uri.includes("}")) throw new Error("transcript URI template left an unresolved placeholder");
  return uri;
}

function validateVerdictReport(value, label) {
  const report = requireExactKeys(value, [
    "problem_id",
    "verifier_version",
    "verifier_image",
    "solution_hash",
    "valid",
    "improvement",
    "score",
    "reason",
    "recomputed_at_commit",
    "details",
  ], label);
  for (const key of ["problem_id", "verifier_version", "verifier_image", "reason", "recomputed_at_commit"]) {
    requireString(report[key], `${label}.${key}`);
  }
  if (!SHA256_RE.test(String(report.solution_hash))) {
    throw new Error(`${label}.solution_hash must be sha256:<64 lowercase hex>`);
  }
  if (typeof report.valid !== "boolean") throw new Error(`${label}.valid must be a boolean`);
  for (const key of ["improvement", "score"]) {
    if (!RATIONAL_RE.test(String(report[key]))) {
      throw new Error(`${label}.${key} must be a normalized rational string`);
    }
  }
  requireObject(report.details, `${label}.details`);
  return report;
}

function validateDurableTranscriptURI(value) {
  const uri = requireString(value, "transcriptURI");
  if (/\s/.test(uri) || !/^(ar|ipfs):\/\//.test(uri) || /^file:/i.test(uri) || uri.includes("..")) {
    throw new Error("transcriptURI must be a durable ar:// or ipfs:// URI");
  }
  return uri;
}

function validateChainClaim(value, expected) {
  const claim = requireObject(value, "transcript.verifier.chain_claim");
  if (claim.schema_version !== "p42-chain-claim/v1") {
    throw new Error("transcript.verifier.chain_claim has an unsupported schema");
  }
  if (!Number.isSafeInteger(claim.chain_id) || claim.chain_id < 1) {
    throw new Error("transcript.verifier.chain_claim.chain_id must be a positive integer");
  }
  const normalized = {
    chain_id: claim.chain_id,
    problem_id: requireString(claim.problem_id, "transcript.verifier.chain_claim.problem_id"),
    submission_contract: normalizedAddress(claim.submission_contract, "transcript.verifier.chain_claim.submission_contract"),
    challenge_contract: normalizedAddress(claim.challenge_contract, "transcript.verifier.chain_claim.challenge_contract"),
    submission_id: nonzeroSubmissionId(claim.submission_id, "transcript.verifier.chain_claim.submission_id"),
    claimed_score_atoms: asInteger(claim.claimed_score_atoms, "transcript.verifier.chain_claim.claimed_score_atoms"),
    reveal_instance_hash: normalizedBytes32(claim.reveal_instance_hash, "transcript.verifier.chain_claim.reveal_instance_hash"),
    challenge_ends_at: asNonnegativeDecimal(claim.challenge_ends_at, "transcript.verifier.chain_claim.challenge_ends_at"),
  };
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (expectedValue === undefined || expectedValue === null) continue;
    if (String(normalized[key]).toLowerCase() !== String(expectedValue).toLowerCase()) {
      throw new Error(`transcript chain claim ${key} does not match the finalized challenge`);
    }
  }
  return normalized;
}

function validateCandidate(value, claim) {
  const candidate = requireExactKeys(value, [
    "schema_version",
    "action",
    "reason_code",
    "chain_id",
    "problem_id",
    "submission_contract",
    "challenge_contract",
    "submission_id",
    "reveal_instance_hash",
    "source_event_hash",
    "evidence_hash",
    "challenge_ends_at",
    "max_bond_wei",
    "candidate_hash",
  ], "transcript.verifier.challenge_candidate");
  if (candidate.schema_version !== "p42-challenge-candidate/v1") {
    throw new Error("transcript verifier candidate has an unsupported schema");
  }
  if (!["challenge", "none", "quarantine"].includes(candidate.action)) {
    throw new Error("transcript verifier candidate action is unsupported");
  }
  requireString(candidate.reason_code, "transcript verifier candidate reason_code");
  if (!Number.isSafeInteger(candidate.chain_id) || candidate.chain_id !== claim.chain_id) {
    throw new Error("transcript verifier candidate chain_id does not match its chain claim");
  }
  if (requireString(candidate.problem_id, "transcript verifier candidate problem_id") !== claim.problem_id) {
    throw new Error("transcript verifier candidate problem_id does not match its chain claim");
  }
  if (!sameAddress(normalizedAddress(candidate.submission_contract, "candidate submission_contract"), claim.submission_contract)) {
    throw new Error("transcript verifier candidate submission_contract does not match its chain claim");
  }
  if (!sameAddress(normalizedAddress(candidate.challenge_contract, "candidate challenge_contract"), claim.challenge_contract)) {
    throw new Error("transcript verifier candidate challenge_contract does not match its chain claim");
  }
  if (nonzeroSubmissionId(candidate.submission_id, "candidate submission_id") !== claim.submission_id) {
    throw new Error("transcript verifier candidate submission_id does not match its chain claim");
  }
  if (!sameBytes32(normalizedBytes32(candidate.reveal_instance_hash, "candidate reveal_instance_hash"), claim.reveal_instance_hash)) {
    throw new Error("transcript verifier candidate reveal_instance_hash does not match its chain claim");
  }
  if (asNonnegativeDecimal(candidate.challenge_ends_at, "candidate challenge_ends_at") !== claim.challenge_ends_at) {
    throw new Error("transcript verifier candidate challenge_ends_at does not match its chain claim");
  }
  if (!SHA256_RE.test(String(candidate.source_event_hash)) || !SHA256_RE.test(String(candidate.evidence_hash))) {
    throw new Error("transcript verifier candidate evidence hashes must be sha256:<64 lowercase hex>");
  }
  if (candidate.max_bond_wei !== null && !DECIMAL_RE.test(String(candidate.max_bond_wei))) {
    throw new Error("transcript verifier candidate max_bond_wei must be null or a non-negative integer string");
  }
  if (!SHA256_RE.test(String(candidate.candidate_hash))) {
    throw new Error("transcript verifier candidate_hash must be sha256:<64 lowercase hex>");
  }
  const unhashed = { ...candidate };
  delete unhashed.candidate_hash;
  if (sha256Canonical(unhashed) !== candidate.candidate_hash) {
    throw new Error("transcript verifier candidate self-hash mismatch");
  }
  return candidate;
}

function validateDecisionEvidence(transcript, candidate) {
  const verifier = requireObject(transcript.verifier, "transcript.verifier");
  if (typeof verifier.ok !== "boolean" || typeof verifier.valid !== "boolean") {
    throw new Error("transcript.verifier ok and valid must be booleans");
  }
  if (!Number.isSafeInteger(verifier.elapsed_ms) || verifier.elapsed_ms < 0) {
    throw new Error("transcript.verifier.elapsed_ms must be a non-negative integer");
  }
  if (verifier.sandbox !== "docker") {
    throw new Error("resolver refuses a transcript not run in the Docker sandbox");
  }
  const hasReport = Object.prototype.hasOwnProperty.call(verifier, "report");
  let report = null;
  if (hasReport) {
    report = validateVerdictReport(verifier.report, "transcript.verifier.report");
    if (!SHA256_RE.test(String(verifier.report_hash)) || sha256Canonical(report) !== verifier.report_hash) {
      throw new Error("transcript verifier report hash mismatch");
    }
  }

  if (candidate.action === "quarantine") {
    throw new Error(`resolver refuses quarantined runner evidence (${candidate.reason_code})`);
  }
  if (candidate.action === "none") {
    if (!report || report.valid !== true || verifier.valid !== true || verifier.ok !== true) {
      throw new Error("solver-favorable decision requires a valid accepted VerdictReport");
    }
    const relation = verifier.claim_comparison?.relation;
    if (!["exact", "claimed_worse_than_verified"].includes(relation)) {
      throw new Error("solver-favorable decision lacks a conservative/exact score comparison");
    }
    return { challengerWins: false, report };
  }

  if (candidate.reason_code === "score_underclaimed") {
    if (!report || report.valid !== true || verifier.valid !== true || verifier.ok !== true) {
      throw new Error("score-underclaimed decision requires a valid accepted VerdictReport");
    }
    if (verifier.claim_comparison?.relation !== "claimed_better_than_verified") {
      throw new Error("score-underclaimed decision lacks the exact adverse score comparison");
    }
    return { challengerWins: true, report };
  }
  if (candidate.reason_code === "verifier_rejected") {
    if (!report || report.valid !== false || verifier.valid !== false || verifier.ok !== false) {
      throw new Error("verifier-rejected decision requires a rejected VerdictReport");
    }
    return { challengerWins: true, report };
  }
  if (candidate.reason_code.startsWith("da_")) {
    const da = requireObject(transcript.da, "transcript.da");
    if (da.ok !== false || da.challengeable !== true || hasReport || verifier.valid !== false || verifier.ok !== false) {
      throw new Error("DA challenge decision has inconsistent verifier or DA evidence");
    }
    return { challengerWins: true, report: null };
  }
  throw new Error(`resolver does not recognize challenge reason ${candidate.reason_code}`);
}

// Validate the persisted worker transcript independently of Python. This is not
// a second verifier; it rejects malformed/misaligned evidence before a bonded
// resolver action can make a chain decision.
export function verifyResolverTranscript(transcriptValue, expected) {
  const transcript = requireExactKeys(transcriptValue, [
    "schema_version",
    "job_id",
    "generated_at_utc",
    "started_at_utc",
    "problem",
    "solution",
    "da",
    "resource_limits",
    "verifier",
    "transcript_hash",
  ], "runner transcript");
  if (transcript.schema_version !== "p42-runner-transcript/v1") {
    throw new Error("runner transcript has an unsupported schema");
  }
  for (const key of ["job_id", "generated_at_utc", "started_at_utc", "problem", "solution"]) {
    requireString(transcript[key], `runner transcript ${key}`);
  }
  if (!SHA256_RE.test(String(transcript.transcript_hash))) {
    throw new Error("runner transcript hash must be sha256:<64 lowercase hex>");
  }
  const unhashed = { ...transcript };
  delete unhashed.transcript_hash;
  if (sha256Canonical(unhashed) !== transcript.transcript_hash) {
    throw new Error("runner transcript self-hash mismatch");
  }
  const limits = requireExactKeys(transcript.resource_limits, [
    "required_memory_mb",
    "memory_safety_factor",
    "child_address_space_limit_mb",
    "address_space_limit_supported",
  ], "runner transcript resource_limits");
  for (const key of ["required_memory_mb", "child_address_space_limit_mb"]) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] < 1) {
      throw new Error(`runner transcript resource_limits.${key} must be a positive integer`);
    }
  }
  if (typeof limits.memory_safety_factor !== "number" || limits.memory_safety_factor < 1) {
    throw new Error("runner transcript resource_limits.memory_safety_factor must be at least one");
  }
  if (typeof limits.address_space_limit_supported !== "boolean") {
    throw new Error("runner transcript resource_limits.address_space_limit_supported must be a boolean");
  }
  const claim = validateChainClaim(transcript.verifier?.chain_claim, expected);
  const candidate = validateCandidate(transcript.verifier?.challenge_candidate, claim);
  const evidence = validateDecisionEvidence(transcript, candidate);
  return {
    transcript,
    claim,
    candidate,
    challengerWins: evidence.challengerWins,
    report: evidence.report,
    transcriptHashBytes32: sha256ToBytes32(transcript.transcript_hash, "runner transcript hash"),
  };
}

export function buildResolverVerdictHash({
  transcriptHash,
  candidateHash,
  challengerWins,
  revealInstanceHash,
  challengeInstanceHash,
}) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  return ethers.keccak256(coder.encode(
    ["bytes32", "bytes32", "bytes32", "bool", "bytes32", "bytes32"],
    [
      ethers.id("p42-resolver-verdict/v1"),
      sha256ToBytes32(transcriptHash, "transcriptHash"),
      sha256ToBytes32(candidateHash, "candidateHash"),
      Boolean(challengerWins),
      normalizedBytes32(revealInstanceHash, "revealInstanceHash"),
      normalizedBytes32(challengeInstanceHash, "challengeInstanceHash"),
    ],
  ));
}

// This intentionally lives beside the resolver until the shared agent library
// can grow a reviewed generic exact-call-policy builder for every action type.
export function buildResolveCallPolicy({
  challengeInterface,
  challengeContract,
  chainId,
  problemId,
  submissionId,
  revealInstanceHash,
  challengeInstanceHash,
  challengerWins,
  transcriptHash,
  transcriptURI,
  verdictHash,
  candidateHash,
  sourceEventHash,
  expiresAt,
  valueWei,
}) {
  const target = normalizedAddress(challengeContract, "challengeContract");
  const reveal = normalizedBytes32(revealInstanceHash, "revealInstanceHash");
  const challenge = normalizedBytes32(challengeInstanceHash, "challengeInstanceHash");
  const transcriptHashBytes32 = sha256ToBytes32(transcriptHash, "transcriptHash");
  const verdict = normalizedBytes32(verdictHash, "verdictHash");
  const uri = validateDurableTranscriptURI(transcriptURI);
  sha256ToBytes32(candidateHash, "candidateHash");
  sha256ToBytes32(sourceEventHash, "sourceEventHash");
  requireString(problemId, "problemId");
  const callValue = BigInt(valueWei);
  if (callValue <= 0n) throw new Error("resolver decision bond must be positive");
  const deadline = BigInt(expiresAt);
  if (deadline <= 0n) throw new Error("resolve policy expiry must be positive");
  if (!Number.isSafeInteger(Number(chainId)) || Number(chainId) < 1) {
    throw new Error("resolve policy chain id must be a positive integer");
  }
  const calldata = challengeInterface.encodeFunctionData("resolve", [
    BigInt(submissionId),
    challenge,
    Boolean(challengerWins),
    transcriptHashBytes32,
    uri,
    verdict,
  ]);
  const selector = challengeInterface.getFunction("resolve").selector;
  const scope = [
    "p42:resolve:v1",
    `chain:${chainId}`,
    `target:${target}`,
    `problem:${problemId}`,
    `submission:${submissionId}`,
    `reveal:${reveal}`,
    `challenge:${challenge}`,
    `transcript:${transcriptHash}`,
    `candidate:${candidateHash}`,
    `event:${sourceEventHash}`,
    `decision:${Boolean(challengerWins) ? "challenger" : "solver"}`,
    `verdict:${verdict}`,
    `uri_hash:${ethers.keccak256(ethers.toUtf8Bytes(uri))}`,
  ].join("|");
  const policy = {
    schema_version: "p42-session-call-policy/v1",
    target,
    selector,
    allowed: true,
    chain_id: Number(chainId),
    expires_at: deadline.toString(),
    max_calls: 1,
    calldata,
    calldata_hash: ethers.keccak256(calldata),
    scope,
    scope_hash: ethers.id(scope),
    call_value_wei: callValue.toString(),
    required_per_call_value_cap_wei: callValue.toString(),
    candidate_hash: candidateHash,
    set_call_policy: {
      function: "setCallPolicy(address,bytes4,bool,uint256,uint64,uint32,bytes32,bytes32)",
      arguments: [
        target,
        selector,
        true,
        String(chainId),
        deadline.toString(),
        1,
        ethers.keccak256(calldata),
        ethers.id(scope),
      ],
    },
    execute: {
      function: "execute(address,uint256,bytes)",
      arguments: [target, callValue.toString(), calldata],
    },
  };
  policy.policy_hash = sha256Canonical(policy);
  return policy;
}

// The resolver policy binds the inner ChallengeManager call. In production the
// session key signs an outer P42AgentWallet.execute transaction, so its journal
// must validate those outer bytes rather than accidentally comparing them to a
// direct EOA resolve call.
export function buildResolverTransportRequest({
  callPolicy,
  executionMode,
  agentWalletInterface = null,
  agentWalletAddress = null,
}) {
  const exact = exactCallRequestFromPolicy(callPolicy, callPolicy.call_value_wei);
  const mode = typeof executionMode === "string" ? executionMode : executionMode?.mode;
  if (mode === "direct-eoa-local-test") return exact;
  if (mode !== "agent-wallet" || !agentWalletInterface || !agentWalletAddress) {
    throw new Error("resolver transport requires an agent wallet outside direct local-test mode");
  }
  return {
    to: normalizedAddress(agentWalletAddress, "agentWalletAddress"),
    data: agentWalletInterface.encodeFunctionData("execute", [exact.to, exact.value, exact.data]),
    value: 0n,
  };
}

export function resolverEventHashFor(event, { chainId, challengeContract, problemId }) {
  const args = event?.args;
  if (!args) throw new Error("Challenged event is missing decoded args");
  const reveal = normalizedBytes32(args.revealInstanceHash, "Challenged revealInstanceHash");
  const challenge = normalizedBytes32(args.challengeInstanceHash, "Challenged challengeInstanceHash");
  return sha256Canonical({
    schema_version: "p42-resolver-challenged-event/v1",
    chain_id: Number(chainId),
    problem_id: String(problemId),
    challenge_contract: normalizedAddress(challengeContract, "challengeContract"),
    submission_id: BigInt(args.submissionId).toString(),
    challenger: normalizedAddress(args.challenger, "Challenged challenger"),
    reason_hash: normalizedBytes32(args.reasonHash, "Challenged reasonHash"),
    challenge_bond_wei: BigInt(args.bondWei).toString(),
    dispute_ends_at: BigInt(args.disputeEndsAt).toString(),
    reveal_instance_hash: reveal,
    challenge_instance_hash: challenge,
    block_number: Number(event.blockNumber),
    block_hash: normalizedBytes32(event.blockHash, "Challenged blockHash"),
    transaction_hash: normalizedBytes32(event.transactionHash, "Challenged transactionHash"),
    transaction_index: Number(event.transactionIndex ?? 0),
    log_index: Number(event.index ?? event.logIndex),
  });
}

function eventDescriptor(event, context) {
  const args = event.args;
  const descriptor = {
    event_hash: resolverEventHashFor(event, context),
    chain_id: context.chainId,
    problem_id: context.problemId,
    challenge_contract: String(context.chal.target).toLowerCase(),
    submission_contract: String(context.subs.target).toLowerCase(),
    submission_id: BigInt(args.submissionId).toString(),
    challenger: normalizedAddress(args.challenger, "Challenged challenger"),
    reason_hash: normalizedBytes32(args.reasonHash, "Challenged reasonHash"),
    challenge_bond_wei: BigInt(args.bondWei).toString(),
    dispute_ends_at: BigInt(args.disputeEndsAt).toString(),
    reveal_instance_hash: normalizedBytes32(args.revealInstanceHash, "Challenged revealInstanceHash"),
    challenge_instance_hash: normalizedBytes32(args.challengeInstanceHash, "Challenged challengeInstanceHash"),
    block_number: Number(event.blockNumber),
    block_hash: normalizedBytes32(event.blockHash, "Challenged blockHash"),
    transaction_hash: normalizedBytes32(event.transactionHash, "Challenged transactionHash"),
    transaction_index: Number(event.transactionIndex ?? 0),
    log_index: Number(event.index ?? event.logIndex),
  };
  if (!Number.isSafeInteger(descriptor.block_number) || descriptor.block_number < context.startBlock) {
    throw new Error("Challenged event has an invalid block number");
  }
  if (!Number.isSafeInteger(descriptor.log_index) || descriptor.log_index < 0) {
    throw new Error("Challenged event has an invalid log index");
  }
  return descriptor;
}

function resolverBinding(context) {
  return {
    schema_version: "p42-resolver-binding/v1",
    chain_id: context.chainId,
    deployment_commit: String(context.manifest.deploymentCommit).toLowerCase(),
    deployment_config_hash: String(context.manifest.deploymentConfigHash).toLowerCase(),
    submission_contract: String(context.subs.target).toLowerCase(),
    challenge_contract: String(context.chal.target).toLowerCase(),
    problem_id: context.problemId,
    manifest_start_block: context.startBlock,
  };
}

function buildResolverCursor(binding, nextBlock, anchors, overlapBlocks) {
  if (!Number.isSafeInteger(nextBlock) || nextBlock < binding.manifest_start_block) {
    throw new Error("resolver cursor next block is invalid");
  }
  const floor = Math.max(binding.manifest_start_block, nextBlock - overlapBlocks - 1);
  return {
    schema_version: "p42-resolver-cursor/v1",
    binding,
    next_block: nextBlock,
    anchors: anchors
      .filter((anchor) => anchor.block_number >= floor)
      .sort((left, right) => left.block_number - right.block_number),
    updated_at_utc: new Date().toISOString(),
  };
}

function validateResolverCursor(cursor, binding) {
  if (cursor?.schema_version !== "p42-resolver-cursor/v1") {
    throw new Error("unsupported resolver cursor schema");
  }
  if (canonicalJson(cursor.binding) !== canonicalJson(binding)) {
    throw new Error("resolver cursor belongs to a different deployment binding");
  }
  if (!Number.isSafeInteger(cursor.next_block) || cursor.next_block < binding.manifest_start_block) {
    throw new Error("resolver cursor next_block is invalid");
  }
  if (!Array.isArray(cursor.anchors)) throw new Error("resolver cursor anchors must be an array");
  for (const anchor of cursor.anchors) {
    if (!Number.isSafeInteger(anchor.block_number) || anchor.block_number < binding.manifest_start_block) {
      throw new Error("resolver cursor anchor block number is invalid");
    }
    normalizedBytes32(anchor.block_hash, "resolver cursor anchor block hash");
  }
  return cursor;
}

function nextResolverScanRange(cursor, startBlock, safeLatest, overlapBlocks) {
  if (!Number.isSafeInteger(safeLatest) || safeLatest < 0) throw new Error("resolver safe latest block is invalid");
  const fromBlock = Math.max(startBlock, cursor.next_block - overlapBlocks);
  return fromBlock > safeLatest ? null : { fromBlock, toBlock: safeLatest };
}

function writeCanonicalAtomic(path, value, mode = 0o600) {
  const text = `${canonicalJson(value)}\n`;
  if (existsSync(path)) {
    if (readFileSync(path, "utf8") !== text) throw new Error(`immutable runtime artifact changed: ${path}`);
    return;
  }
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, text, { encoding: "utf8", mode, flag: "wx" });
  renameSync(temporary, path);
}

function writeMutableAtomic(path, value, mode = 0o600) {
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${canonicalJson(value)}\n`, { encoding: "utf8", mode, flag: "w" });
  renameSync(temporary, path);
}

function loadResolverState(context) {
  if (!existsSync(context.statePath)) {
    return {
      schema_version: "p42-resolver-state/v1",
      binding: context.binding,
      actions: {},
      updated_at_utc: new Date().toISOString(),
    };
  }
  const state = JSON.parse(readFileSync(context.statePath, "utf8"));
  if (state.schema_version !== "p42-resolver-state/v1") throw new Error("unsupported resolver state schema");
  if (canonicalJson(state.binding) !== canonicalJson(context.binding)) {
    throw new Error("resolver state belongs to a different deployment binding");
  }
  requireObject(state.actions, "resolver state actions");
  return state;
}

function persistState(context) {
  context.state.updated_at_utc = new Date().toISOString();
  writeMutableAtomic(context.statePath, context.state);
}

function loadCursor(context) {
  if (!existsSync(context.cursorPath)) {
    return buildResolverCursor(context.binding, context.startBlock, [], context.reorgOverlapBlocks);
  }
  return validateResolverCursor(JSON.parse(readFileSync(context.cursorPath, "utf8")), context.binding);
}

async function persistCursor(context, nextBlock) {
  const floor = Math.max(context.startBlock, nextBlock - context.reorgOverlapBlocks - 1);
  const anchors = [];
  for (let blockNumber = floor; blockNumber < nextBlock; blockNumber += 1) {
    const block = await context.provider.getBlock(blockNumber);
    if (block?.hash) anchors.push({ block_number: blockNumber, block_hash: String(block.hash).toLowerCase() });
  }
  context.cursor = buildResolverCursor(context.binding, nextBlock, anchors, context.reorgOverlapBlocks);
  writeMutableAtomic(context.cursorPath, context.cursor);
}

async function cursorAnchorMismatch(context) {
  for (const anchor of context.cursor.anchors) {
    const block = await context.provider.getBlock(anchor.block_number);
    if (!block || !sameBytes32(block.hash, anchor.block_hash)) return anchor.block_number;
  }
  return null;
}

function appendAlert(context, message) {
  const line = `${new Date().toISOString()} ${message}`;
  console.error(`  !!! ${line}`);
  appendFileSync(context.alertPath, `${line}\n`, { encoding: "utf8", mode: 0o600 });
}

function readTranscript(path) {
  const stats = statSync(path);
  if (!stats.isFile() || stats.size > MAX_TRANSCRIPT_BYTES) {
    throw new Error(`transcript ${path} is not a regular file within the ${MAX_TRANSCRIPT_BYTES} byte limit`);
  }
  return JSON.parse(readFileSync(path, "utf8"));
}

function rawClaimIdentity(transcript) {
  const claim = transcript?.verifier?.chain_claim;
  if (!claim || typeof claim !== "object" || Array.isArray(claim)) return null;
  return {
    chain_id: claim.chain_id,
    problem_id: claim.problem_id,
    submission_contract: typeof claim.submission_contract === "string" ? claim.submission_contract.toLowerCase() : null,
    challenge_contract: typeof claim.challenge_contract === "string" ? claim.challenge_contract.toLowerCase() : null,
    submission_id: claim.submission_id,
    reveal_instance_hash: typeof claim.reveal_instance_hash === "string" ? claim.reveal_instance_hash.toLowerCase() : null,
  };
}

function identityCouldMatch(identity, event) {
  return identity
    && identity.chain_id === event.chain_id
    && identity.problem_id === event.problem_id
    && identity.submission_contract === event.submission_contract
    && identity.challenge_contract === event.challenge_contract
    && String(identity.submission_id) === event.submission_id
    && identity.reveal_instance_hash === event.reveal_instance_hash;
}

function findTranscriptForEvent(context, event) {
  const matches = [];
  const invalid = [];
  for (const entry of readdirSync(context.transcriptsPath, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const path = join(context.transcriptsPath, entry.name);
    let raw;
    try {
      raw = readTranscript(path);
    } catch (error) {
      continue;
    }
    if (!identityCouldMatch(rawClaimIdentity(raw), event)) continue;
    try {
      matches.push({
        path,
        checked: verifyResolverTranscript(raw, {
          chain_id: event.chain_id,
          problem_id: event.problem_id,
          submission_contract: event.submission_contract,
          challenge_contract: event.challenge_contract,
          submission_id: event.submission_id,
          reveal_instance_hash: event.reveal_instance_hash,
        }),
      });
    } catch (error) {
      invalid.push(`${path}: ${error.message}`);
    }
  }
  if (invalid.length) throw new Error(`matching transcript failed validation: ${invalid.join("; ")}`);
  if (matches.length !== 1) {
    throw new Error(matches.length === 0
      ? "no canonical runner transcript matches this finalized challenge"
      : `ambiguous canonical runner transcripts (${matches.length}) match this finalized challenge`);
  }
  return matches[0];
}

function actionPaths(context, eventHash, policyHash) {
  const prefix = `${eventHash.slice(7)}-${policyHash.slice(7, 23)}`;
  return {
    policyPath: join(context.actionsPath, `${prefix}.policy.json`),
    signedPath: join(context.actionsPath, `${prefix}.signed-tx.json`),
  };
}

function assertActionPolicy(action, context) {
  const policy = requireObject(action.call_policy, "resolver action call_policy");
  const unsigned = { ...policy };
  const policyHash = unsigned.policy_hash;
  delete unsigned.policy_hash;
  if (policyHash !== sha256Canonical(unsigned) || action.call_policy_hash !== policyHash) {
    throw new Error("resolver action call policy self-hash mismatch");
  }
  if (canonicalJson(JSON.parse(readFileSync(action.call_policy_path, "utf8"))) !== canonicalJson(policy)) {
    throw new Error("resolver action call policy differs from its immutable artifact");
  }
  const decoded = context.chal.interface.decodeFunctionData("resolve", policy.calldata);
  const [submissionId, challengeInstanceHash, challengerWins, transcriptHash, transcriptURI, verdictHash] = decoded;
  if (
    BigInt(submissionId).toString() !== action.submission_id
    || !sameBytes32(challengeInstanceHash, action.challenge_instance_hash)
    || Boolean(challengerWins) !== Boolean(action.challenger_wins)
    || !sameBytes32(transcriptHash, action.transcript_hash_bytes32)
    || transcriptURI !== action.transcript_uri
    || !sameBytes32(verdictHash, action.verdict_hash)
    || !sameAddress(policy.target, context.chal.target)
    || BigInt(policy.call_value_wei) !== BigInt(action.bond_wei)
    || BigInt(policy.expires_at) !== BigInt(action.dispute_ends_at)
  ) {
    throw new Error("resolver action call policy is not bound to its persisted decision");
  }
  return policy;
}

async function currentChallenge(context, action) {
  const submissionId = BigInt(action.submission_id);
  const [submission, challenge, liveReveal, challengeReveal, challengeInstance, resolverAddress, latest, bond] = await Promise.all([
    context.subs.submissions(submissionId),
    context.chal.challenges(submissionId),
    context.subs.revealInstanceHashOf(submissionId),
    context.chal.challengeRevealInstanceHashOf(submissionId),
    context.chal.challengeInstanceHashOf(submissionId),
    context.chal.resolver(),
    context.provider.getBlock("latest"),
    context.chal.resolverDecisionBondWei(),
  ]);
  const expectedResolver = context.executionMode.mode === "agent-wallet"
    ? context.executionMode.agentWalletAddress
    : context.wallet.address.toLowerCase();
  if (!sameAddress(resolverAddress, expectedResolver)) {
    return { ok: false, terminal: true, reason: "challenge contract resolver role does not match this runtime execution address" };
  }
  if (Number(submission.status) !== 3) return { ok: false, terminal: true, reason: `submission status is ${submission.status}` };
  if (!sameAddress(challenge.challenger, action.challenger)) {
    return { ok: false, terminal: true, reason: "live challenger does not match finalized Challenged event" };
  }
  if (!sameBytes32(challenge.reasonHash, action.reason_hash)) {
    return { ok: false, terminal: true, reason: "live challenge reason hash does not match finalized Challenged event" };
  }
  if (BigInt(challenge.disputeEndsAt) !== BigInt(action.dispute_ends_at)) {
    return { ok: false, terminal: true, reason: "live dispute deadline does not match finalized Challenged event" };
  }
  for (const [label, observed, expected] of [
    ["submission reveal instance", liveReveal, action.reveal_instance_hash],
    ["challenge reveal instance", challengeReveal, action.reveal_instance_hash],
    ["challenge instance", challengeInstance, action.challenge_instance_hash],
  ]) {
    if (!sameBytes32(observed, expected)) return { ok: false, terminal: true, reason: `${label} changed after finalization` };
  }
  if (challenge.resolved || challenge.decisionPending) {
    const matchesDecision = challenge.decisionPending
      && sameBytes32(challenge.transcriptHash, action.transcript_hash_bytes32)
      && sameBytes32(challenge.verdictHash, action.verdict_hash)
      && Boolean(challenge.challengerWins) === Boolean(action.challenger_wins);
    return {
      ok: false,
      terminal: true,
      status: matchesDecision ? "onchain_observed" : "resolved_elsewhere",
      reason: matchesDecision ? "live chain already records this resolver decision" : "live challenge already has another terminal decision",
    };
  }
  if (!latest || BigInt(latest.timestamp) >= BigInt(challenge.disputeEndsAt)) {
    return { ok: false, terminal: true, reason: "dispute window closed before resolver action" };
  }
  if (BigInt(bond) <= 0n) return { ok: false, terminal: true, reason: "resolver decision bond is zero" };
  const manifestBond = context.manifest.parameters?.resolverDecisionBondWei;
  if (manifestBond === undefined || BigInt(manifestBond) !== BigInt(bond)) {
    return { ok: false, terminal: true, reason: "manifest resolver decision bond does not match live contract" };
  }
  return { ok: true, latestTimestamp: BigInt(latest.timestamp), bond: BigInt(bond) };
}

async function assertAgentWalletPolicy(context, callPolicy, bond, latestTimestamp) {
  const [
    sessionKey,
    sessionChainId,
    sessionExpiresAt,
    revoked,
    perCallCap,
    totalCap,
    spentWei,
    allowed,
    policy,
  ] = await Promise.all([
    context.agentWallet.sessionKey(),
    context.agentWallet.sessionChainId(),
    context.agentWallet.sessionExpiresAt(),
    context.agentWallet.revoked(),
    context.agentWallet.perCallValueCapWei(),
    context.agentWallet.totalSpendCapWei(),
    context.agentWallet.spentWei(),
    context.agentWallet.allowed(callPolicy.target, callPolicy.selector),
    context.agentWallet.callPolicies(callPolicy.target, callPolicy.selector),
  ]);
  if (!sameAddress(sessionKey, context.wallet.address)) throw new Error("P42AgentWallet session key does not match RESOLVER_PRIVATE_KEY");
  if (Number(sessionChainId) !== context.chainId) throw new Error("P42AgentWallet session chain mismatch");
  if (revoked) throw new Error("P42AgentWallet session key is revoked");
  if (BigInt(sessionExpiresAt) <= latestTimestamp) throw new Error("P42AgentWallet session is expired");
  if (BigInt(perCallCap) < bond) throw new Error("P42AgentWallet per-call cap is below the resolver decision bond");
  if (BigInt(spentWei) + bond > BigInt(totalCap)) throw new Error("P42AgentWallet total spend cap is exhausted");
  if (allowed !== true) throw new Error("P42AgentWallet target/selector is not allowlisted");
  if (policy.configured !== true) throw new Error("P42AgentWallet exact calldata policy is missing");
  if (Number(policy.chainId) !== context.chainId) throw new Error("P42AgentWallet call policy chain mismatch");
  if (BigInt(policy.expiresAt) < BigInt(callPolicy.expires_at) || BigInt(policy.expiresAt) <= latestTimestamp) {
    throw new Error("P42AgentWallet call policy expiry is insufficient");
  }
  if (Number(policy.maxCalls) !== 1 || Number(policy.calls) !== 0) {
    throw new Error("P42AgentWallet call policy is not a fresh one-call resolver policy");
  }
  if (!sameBytes32(policy.calldataHash, callPolicy.calldata_hash)) {
    throw new Error("P42AgentWallet call policy calldata hash mismatch");
  }
  if (!sameBytes32(policy.scopeHash, callPolicy.scope_hash)) {
    throw new Error("P42AgentWallet call policy scope hash mismatch");
  }
}

async function buildResolveTransactionRequest(context, action, current) {
  const callPolicy = action.call_policy;
  const request = buildResolverTransportRequest({
    callPolicy,
    executionMode: context.executionMode,
    agentWalletInterface: context.agentWallet?.interface,
    agentWalletAddress: context.executionMode.agentWalletAddress,
  });
  if (context.executionMode.mode === "direct-eoa-local-test") {
    await context.provider.call({ ...request, from: context.wallet.address });
    return context.wallet.populateTransaction(request);
  }
  await assertAgentWalletPolicy(context, callPolicy, current.bond, current.latestTimestamp);
  await context.agentWallet.execute.staticCall(callPolicy.target, current.bond, callPolicy.calldata);
  return context.wallet.populateTransaction(request);
}

function assertSignedRecord(record, action, context) {
  if (record?.schema_version !== "p42-signed-transaction/v1") {
    throw new Error("signed resolver journal has an unsupported schema");
  }
  if (!sameBytes32(ethers.keccak256(record.raw_tx), record.hash)) throw new Error("signed resolver journal raw transaction hash mismatch");
  const transaction = ethers.Transaction.from(record.raw_tx);
  if (!sameAddress(transaction.from, context.wallet.address) || !sameAddress(record.signer, context.wallet.address)) {
    throw new Error("signed resolver journal signer mismatch");
  }
  const expected = buildResolverTransportRequest({
    callPolicy: action.call_policy,
    executionMode: context.executionMode,
    agentWalletInterface: context.agentWallet?.interface,
    agentWalletAddress: context.executionMode.agentWalletAddress,
  });
  if (!sameAddress(transaction.to, expected.to) || !sameBytes32(ethers.keccak256(transaction.data), ethers.keccak256(expected.data))) {
    throw new Error("signed resolver journal does not contain the exact resolve call");
  }
  if (transaction.value !== BigInt(expected.value) || Number(transaction.chainId) !== context.chainId) {
    throw new Error("signed resolver journal value or chain mismatch");
  }
  return record;
}

async function ensureSignedAction(context, action) {
  assertActionPolicy(action, context);
  if (existsSync(action.signed_tx_path)) {
    const record = assertSignedRecord(JSON.parse(readFileSync(action.signed_tx_path, "utf8")), action, context);
    if (action.transaction_hash && !sameBytes32(action.transaction_hash, record.hash)) {
      throw new Error("resolver action transaction hash disagrees with its signed journal");
    }
    if (!action.transaction_hash || action.status === "prepared") {
      action.transaction_hash = record.hash;
      action.status = "signed";
      persistState(context);
    }
    return record;
  }
  const current = await currentChallenge(context, action);
  if (!current.ok) {
    action.status = current.status ?? "superseded";
    action.detail = current.reason;
    persistState(context);
    return null;
  }
  const request = await buildResolveTransactionRequest(context, action, current);
  const record = await buildSignedTransactionRecord({
    wallet: context.wallet,
    request,
    label: `resolve:${action.submission_id}:${action.challenge_instance_hash}:${action.transcript_hash}`,
  });
  // The raw bytes land on disk before the mutable action state can say signed.
  writeCanonicalAtomic(action.signed_tx_path, record);
  assertSignedRecord(record, action, context);
  action.transaction_hash = record.hash;
  action.status = "signed";
  persistState(context);
  return record;
}

async function reconcileAction(context, action) {
  if (TERMINAL_ACTIONS.has(action.status) || action.canonical_status === "orphaned_reorg" || !action.call_policy) return;
  const record = await ensureSignedAction(context, action);
  if (!record) return;
  let receipt = await context.provider.getTransactionReceipt(record.hash);
  if (receipt) {
    const block = await context.provider.getBlock(receipt.blockNumber);
    const receiptState = classifyReceiptFinality({
      receiptBlockNumber: receipt.blockNumber,
      receiptBlockHash: receipt.blockHash,
      canonicalBlockHash: block?.hash,
      latestBlockNumber: await context.provider.getBlockNumber(),
      confirmations: context.finalityConfirmations,
    });
    if (receiptState === "reorged") {
      action.status = "reorged";
      action.detail = "receipt block is no longer canonical";
      persistState(context);
      appendAlert(context, `REORGED RESOLUTION ${action.event_hash}: receipt block is no longer canonical`);
      receipt = null;
    } else if (receiptState === "submitted") {
      action.status = "submitted";
      action.detail = `receipt in canonical block ${receipt.blockNumber}, awaiting finality`;
      persistState(context);
      return;
    } else {
      action.status = receipt.status === 1 ? "confirmed" : "broadcast_reverted";
      action.detail = `canonical receipt status ${receipt.status}`;
      persistState(context);
      return;
    }
  }
  let pending = await context.provider.getTransaction(record.hash);
  if (!pending) {
    const current = await currentChallenge(context, action);
    if (!current.ok) {
      action.status = current.status ?? "superseded";
      action.detail = current.reason;
      persistState(context);
      if (action.status !== "onchain_observed") appendAlert(context, `SUPPRESSED RESOLUTION ${action.event_hash}: ${current.reason}`);
      return;
    }
    try {
      pending = await context.provider.broadcastTransaction(record.raw_tx);
    } catch (error) {
      pending = await context.provider.getTransaction(record.hash);
      if (!pending) throw error;
    }
  }
  action.status = "broadcast";
  action.detail = "raw signed resolve transaction is pending or was rebroadcast";
  persistState(context);
}

async function prepareAction(context, event) {
  const existing = context.state.actions[event.event_hash];
  if (existing && !["awaiting_transcript", "invalid_transcript", "ambiguous_transcript"].includes(existing.status)) {
    return existing;
  }
  let transcript;
  try {
    transcript = findTranscriptForEvent(context, event);
  } catch (error) {
    const status = /no canonical runner transcript/.test(error.message)
      ? "awaiting_transcript"
      : /ambiguous/.test(error.message)
        ? "ambiguous_transcript"
        : "invalid_transcript";
    context.state.actions[event.event_hash] = {
      schema_version: "p42-resolver-action/v1",
      event,
      event_hash: event.event_hash,
      status,
      canonical_status: "canonical",
      detail: error.message,
      created_at_utc: new Date().toISOString(),
    };
    persistState(context);
    appendAlert(context, `REFUSED RESOLUTION ${event.event_hash}: ${error.message}`);
    return context.state.actions[event.event_hash];
  }
  const checked = transcript.checked;
  const transcriptURI = expandTranscriptUri(context.transcriptUriTemplate, checked.transcript.transcript_hash);
  const verdictHash = buildResolverVerdictHash({
    transcriptHash: checked.transcript.transcript_hash,
    candidateHash: checked.candidate.candidate_hash,
    challengerWins: checked.challengerWins,
    revealInstanceHash: event.reveal_instance_hash,
    challengeInstanceHash: event.challenge_instance_hash,
  });
  const current = await currentChallenge(context, {
    ...event,
    transcript_hash_bytes32: checked.transcriptHashBytes32,
    verdict_hash: verdictHash,
    challenger_wins: checked.challengerWins,
  });
  if (!current.ok) {
    const action = {
      schema_version: "p42-resolver-action/v1",
      event,
      event_hash: event.event_hash,
      status: current.status ?? "superseded",
      canonical_status: "canonical",
      detail: current.reason,
      created_at_utc: new Date().toISOString(),
    };
    context.state.actions[event.event_hash] = action;
    persistState(context);
    return action;
  }
  const callPolicy = buildResolveCallPolicy({
    challengeInterface: context.chal.interface,
    challengeContract: String(context.chal.target),
    chainId: context.chainId,
    problemId: context.problemId,
    submissionId: event.submission_id,
    revealInstanceHash: event.reveal_instance_hash,
    challengeInstanceHash: event.challenge_instance_hash,
    challengerWins: checked.challengerWins,
    transcriptHash: checked.transcript.transcript_hash,
    transcriptURI,
    verdictHash,
    candidateHash: checked.candidate.candidate_hash,
    sourceEventHash: event.event_hash,
    expiresAt: event.dispute_ends_at,
    valueWei: current.bond,
  });
  const paths = actionPaths(context, event.event_hash, callPolicy.policy_hash);
  writeCanonicalAtomic(paths.policyPath, callPolicy);
  const action = {
    schema_version: "p42-resolver-action/v1",
    event,
    event_hash: event.event_hash,
    canonical_status: "canonical",
    status: "prepared",
    created_at_utc: new Date().toISOString(),
    transcript_path: transcript.path,
    transcript_hash: checked.transcript.transcript_hash,
    transcript_hash_bytes32: checked.transcriptHashBytes32,
    candidate_hash: checked.candidate.candidate_hash,
    challenger_wins: checked.challengerWins,
    verdict_hash: verdictHash,
    transcript_uri: transcriptURI,
    bond_wei: current.bond.toString(),
    ...event,
    call_policy_path: paths.policyPath,
    call_policy_hash: callPolicy.policy_hash,
    call_policy: callPolicy,
    signed_tx_path: paths.signedPath,
  };
  context.state.actions[event.event_hash] = action;
  persistState(context);
  return action;
}

function markOrphanedActions(context, fromBlock, toBlock, eventHashes) {
  for (const action of Object.values(context.state.actions)) {
    const event = action?.event;
    if (!event || action.canonical_status !== "canonical") continue;
    if (event.block_number < fromBlock || event.block_number > toBlock) continue;
    if (eventHashes.has(action.event_hash)) continue;
    action.canonical_status = "orphaned_reorg";
    action.status = "orphaned_reorg";
    action.detail = "finalized Challenged event disappeared from a canonical rescan";
    appendAlert(context, `ORPHANED RESOLUTION ${action.event_hash}: challenged event disappeared on rescan`);
  }
}

async function scanOnce(context) {
  const mismatch = await cursorAnchorMismatch(context);
  if (mismatch !== null) {
    appendAlert(context, `REORG detected at resolver anchor ${mismatch}; rewinding finalized scan`);
    context.cursor = buildResolverCursor(
      context.binding,
      mismatch,
      context.cursor.anchors.filter((anchor) => anchor.block_number < mismatch),
      context.reorgOverlapBlocks,
    );
    writeMutableAtomic(context.cursorPath, context.cursor);
  }
  const latest = await context.provider.getBlockNumber();
  const safeLatest = Math.max(0, latest - context.finalityConfirmations);
  const range = nextResolverScanRange(context.cursor, context.startBlock, safeLatest, context.reorgOverlapBlocks);
  if (range) {
    const logs = await queryChunked(context.chal, context.chal.filters.Challenged(), range.fromBlock, range.toBlock);
    const events = [];
    for (const log of logs) {
      const block = await context.provider.getBlock(log.blockNumber);
      if (!block || !sameBytes32(block.hash, log.blockHash)) {
        throw new Error(`Challenged log at block ${log.blockNumber} is no longer canonical during scan`);
      }
      events.push(eventDescriptor(log, context));
    }
    events.sort((left, right) => left.block_number - right.block_number || left.log_index - right.log_index);
    const hashes = new Set(events.map((event) => event.event_hash));
    markOrphanedActions(context, range.fromBlock, range.toBlock, hashes);
    for (const event of events) await prepareAction(context, event);
    persistState(context);
    await persistCursor(context, range.toBlock + 1);
  }
  for (const action of Object.values(context.state.actions)) {
    try {
      await reconcileAction(context, action);
    } catch (error) {
      action.detail = `reconcile error: ${error.shortMessage || error.message}`;
      persistState(context);
      appendAlert(context, `RESOLVER ACTION ERROR ${action.event_hash}: ${error.shortMessage || error.message}`);
    }
  }
}

async function buildContext(argv) {
  const manifestPath = arg(argv, "manifest");
  const problemId = arg(argv, "problem-id");
  const transcriptsArg = arg(argv, "transcripts");
  const transcriptUriTemplate = arg(argv, "transcript-uri-template");
  const localTest = Boolean(arg(argv, "local-test", false));
  const agentWalletAddress = arg(argv, "agent-wallet", null);
  if (!manifestPath || !problemId || !transcriptsArg || !transcriptUriTemplate) {
    throw new Error("required: --manifest <path> --problem-id <id> --transcripts <dir> --transcript-uri-template <ar://|ipfs://...{transcript_hash}>");
  }
  validateTranscriptUriTemplate(transcriptUriTemplate);
  const privateKey = process.env.RESOLVER_PRIVATE_KEY;
  if (!privateKey) throw new Error("set RESOLVER_PRIVATE_KEY to the resolver session key");
  const manifest = JSON.parse(readFileSync(resolve(manifestPath), "utf8"));
  validateManifestEvidence(manifest);
  const provider = new ethers.JsonRpcProvider(arg(argv, "rpc", "https://sepolia.base.org"));
  const wallet = new ethers.Wallet(privateKey, provider);
  const abi = (name) => JSON.parse(
    readFileSync(resolve(HERE, "..", "contracts", "artifacts", "src", `${name}.sol`, `${name}.json`), "utf8"),
  ).abi;
  const subs = new ethers.Contract(manifest.contracts.submissions.address, abi("P42SubmissionManager"), wallet);
  const chal = new ethers.Contract(manifest.contracts.challenges.address, abi("P42ChallengeManager"), wallet);
  const network = await provider.getNetwork();
  const chainId = Number(network.chainId);
  if (chainId !== Number(manifest.network.chainId)) {
    throw new Error(`manifest chain ${manifest.network.chainId} does not match RPC chain ${chainId}`);
  }
  const { confirmations, reorgOverlapBlocks } = resolveOperatorFinality({
    manifest,
    confirmations: arg(argv, "confirmations", null),
    reorgOverlapBlocks: arg(argv, "reorg-overlap-blocks", null),
    localTest,
  });
  const executionMode = validateOperatorExecutionMode({
    manifest,
    chainId,
    localTest,
    agentWalletAddress,
    operatorAddress: wallet.address,
  });
  const runtime = resolve(arg(argv, "runtime", join(HERE, "runtime", "resolver", String(problemId))));
  const transcriptsPath = resolve(transcriptsArg);
  if (!existsSync(transcriptsPath) || !statSync(transcriptsPath).isDirectory()) {
    throw new Error(`--transcripts must name an existing directory: ${transcriptsPath}`);
  }
  const context = {
    manifest,
    provider,
    wallet,
    subs,
    chal,
    chainId,
    problemId: String(problemId),
    startBlock: Number(arg(argv, "from-block", manifest.indexer.startBlock)),
    finalityConfirmations: confirmations,
    reorgOverlapBlocks,
    executionMode,
    agentWallet: null,
    transcriptUriTemplate,
    transcriptsPath,
    runtime,
    cursorPath: resolve(arg(argv, "cursor", join(runtime, "resolver-cursor.json"))),
    statePath: resolve(arg(argv, "state", join(runtime, "resolver-state.json"))),
    actionsPath: join(runtime, "actions"),
    alertPath: join(runtime, "ALERTS.log"),
  };
  if (!Number.isSafeInteger(context.startBlock) || context.startBlock !== Number(manifest.indexer.startBlock)) {
    throw new Error("--from-block must equal manifest.indexer.startBlock so active challenges cannot be skipped");
  }
  for (const path of [runtime, context.actionsPath]) mkdirSync(path, { recursive: true, mode: 0o700 });
  context.binding = resolverBinding(context);
  context.cursor = loadCursor(context);
  context.state = loadResolverState(context);
  if (executionMode.mode === "agent-wallet") {
    context.agentWallet = new ethers.Contract(executionMode.agentWalletAddress, abi("P42AgentWallet"), wallet);
  }
  return context;
}

async function main(argv = process.argv.slice(2)) {
  const context = await buildContext(argv);
  const once = Boolean(arg(argv, "once", false));
  const pollMs = Number(arg(argv, "poll-ms", "12000"));
  if (!Number.isSafeInteger(pollMs) || pollMs < 250) throw new Error("--poll-ms must be an integer of at least 250");
  console.log(`P42 resolver ${context.wallet.address} chain=${context.chainId} mode=${context.executionMode.mode}`);
  console.log(`transcripts=${context.transcriptsPath} cursor=${context.cursorPath} finality=${context.finalityConfirmations} overlap=${context.reorgOverlapBlocks}`);
  try {
    await scanOnce(context);
    if (once) {
      console.log("[once] done");
      return;
    }
    for (;;) {
      await sleep(pollMs);
      try {
        await scanOnce(context);
      } catch (error) {
        appendAlert(context, `SCAN ERROR: ${error.shortMessage || error.message}`);
      }
    }
  } finally {
    context.provider.destroy();
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  main().catch((error) => {
    console.error("FAILED:", error.shortMessage || error.message);
    process.exitCode = 1;
  });
}
