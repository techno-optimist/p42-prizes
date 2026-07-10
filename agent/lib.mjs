// Shared helpers for the P42 agent clients (solver, operator, indexer).
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { ethers } from "ethers";

// Rational "improvement" -> integer atoms over a fixed 1e6 denominator.
// Single-solver-safe; solver and operator MUST agree on this scale so the
// operator can detect an inflated claim.
// NOTE: since the absolute-score frontier landed (audit F1/F6), improvementAtoms
// is informational only — the payout credit is driven by claimedScoreAtoms
// (see atomsFromScore / SCORE_SCALE below), whose 1e18 scale is fine enough for
// every problem's MIN_IMPROVEMENT (the 1e6 scale here was a million x too coarse).
export const IMPROVEMENT_SCALE = 1_000_000n;

export function atomsFromImprovement(improvement) {
  const [num, den = "1"] = String(improvement).split("/");
  return (BigInt(num) * IMPROVEMENT_SCALE) / BigInt(den);
}

// SHARED FIXED-POINT CONVENTION (must match P42SubmissionManager.SCORE_ATOM_SCALE
// and the deploy scripts): every verifier reports an ABSOLUTE minimization score
// (lower is better) as an exact rational; on chain it is encoded as
//   score_atoms = ceil(score * SCORE_SCALE)   (int256)
// CEIL means the score is never under-reported, so the marginal credit
// (previous bestScoreAtoms - new score_atoms) is never over-stated —
// conservative on the money side. For integer scores the encoding is exact.
export const SCORE_SCALE = 1_000_000_000_000_000_000n; // 1e18

// Parse an exact rational string "num/den" (den optional, default 1) into a
// normalized {num, den} with den > 0.
function parseRational(value) {
  const text = String(value).trim();
  const [numStr, denStr = "1"] = text.split("/");
  let num = BigInt(numStr);
  let den = BigInt(denStr);
  if (den === 0n) throw new Error(`rational ${text} has a zero denominator`);
  if (den < 0n) { num = -num; den = -den; }
  return { num, den };
}

// ceil(score_num * SCORE_SCALE / score_den) as a BigInt — the exact ceiling of
// the scaled rational (works for negative scores too: BigInt division truncates
// toward zero, which for negatives IS the ceiling).
export function atomsFromScore(score) {
  const { num, den } = parseRational(score);
  const scaled = num * SCORE_SCALE;
  let q = scaled / den;
  if (scaled % den !== 0n && scaled > 0n) q += 1n;
  return q;
}

// The on-chain frontier is a MINIMIZATION frontier (lower atoms win). Problems
// whose native objective is `maximize` (problem.yaml objective.direction) are
// mapped by negation so both directions share one on-chain convention. ceil of
// the negated rational rounds a maximize score DOWN — still conservative.
export function chainScoreAtoms(score, direction = "minimize") {
  if (direction !== "minimize" && direction !== "maximize") {
    throw new Error(`unknown objective direction: ${direction}`);
  }
  if (direction === "minimize") return atomsFromScore(score);
  const { num, den } = parseRational(score);
  return atomsFromScore(`${-num}/${den}`);
}

// Minimal problem.yaml probe for the one field the agents need: the objective
// direction. The manifest schema is flat enough that a line-oriented parse is
// exact; no YAML dep. (Seed scores are a deploy-time concern — the open-witness
// seeding flow reads them in the deploy scripts, not here.)
export function problemObjective(problemDir) {
  // Fail CLOSED: the direction decides whether a score is negated onto the
  // minimization frontier, and the solver + operator SHARE this helper. A silent
  // "minimize" default on an unreadable/renamed manifest would make a maximize
  // problem's claim wrongly beat the frontier AND make the operator compute the
  // same wrong truth (so it would not flag it). Throw instead of guessing (audit
  // F1 review).
  let text = "";
  try {
    text = readFileSync(`${problemDir}/problem.yaml`, "utf8");
  } catch (e) {
    throw new Error(`problemObjective: cannot read ${problemDir}/problem.yaml: ${e.message}`);
  }
  const direction = /^\s*direction:\s*(minimize|maximize)\s*$/m.exec(text)?.[1];
  if (!direction) throw new Error(`problemObjective: no 'direction: minimize|maximize' in ${problemDir}/problem.yaml`);
  return { direction };
}

export function problemRunnerConfig(problemDir) {
  let text = "";
  try {
    text = readFileSync(`${problemDir}/problem.yaml`, "utf8");
  } catch (e) {
    throw new Error(`problemRunnerConfig: cannot read ${problemDir}/problem.yaml: ${e.message}`);
  }
  const problemId = /^problem_id:\s*([^\s#]+)\s*$/m.exec(text)?.[1];
  const direction = /^\s*direction:\s*(minimize|maximize)\s*$/m.exec(text)?.[1];
  const memory = /^\s*memory_mb:\s*([0-9]+)\s*$/m.exec(text)?.[1];
  const wall = /^\s*wall_seconds:\s*([0-9]+)\s*$/m.exec(text)?.[1];
  if (!problemId || !direction || !memory || !wall) {
    throw new Error(`problemRunnerConfig: problem id, objective direction, and verifier memory/wall limits are required in ${problemDir}/problem.yaml`);
  }
  return { problemId, direction, requiredMemoryMb: Number(memory), wallSeconds: Number(wall) };
}

// Run the problem's exact verifier on a solution file and return the parsed
// VerdictReport. The verifier exits 1 on an invalid solution but still prints
// the canonical report to stdout, so capture stdout on a non-zero exit too.
export function runVerifier(problemDir, solutionPath, repoRoot) {
  const { wallSeconds } = problemRunnerConfig(problemDir);
  let out;
  try {
    out = execFileSync("python3", ["-m", "p42_prizes.cli", "verify", "--problem", problemDir, "--solution", solutionPath], {
      encoding: "utf8",
      timeout: (wallSeconds + 5) * 1000,
      maxBuffer: 16 * 1024 * 1024,
      env: {
        PATH: process.env.PATH || "/usr/bin:/bin",
        PYTHONPATH: `${repoRoot}/src`,
        PYTHONHASHSEED: "0",
        OMP_NUM_THREADS: "1",
        OPENBLAS_NUM_THREADS: "1",
        MKL_NUM_THREADS: "1",
      },
    });
  } catch (e) {
    if (e.code === "ETIMEDOUT") throw new Error(`verifier timed out after ${wallSeconds + 5}s`);
    out = e.stdout || "";
  }
  const line = out.trim();
  if (!line) throw new Error("verifier produced no VerdictReport");
  return JSON.parse(line);
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256Canonical(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function normalizedBytes32(value, label) {
  if (!ethers.isHexString(value, 32)) throw new Error(`${label} must be 32-byte hex`);
  return String(value).toLowerCase();
}

// Recover a reveal call from direct calldata or any ABI wrapper (P42AgentWallet,
// ERC-4337 account/EntryPoint, multisend, etc.). Dynamic bytes preserve the
// nested call verbatim, so scanning for the selector and validating every
// decoded field against the Revealed log is both wrapper-agnostic and bound to
// the exact event being processed. When commitDaHash is supplied, matching log
// context is not enough: every candidate must also hash to the committed bytes
// anchor, and any extra candidate/decoy fails closed.
export function recoverRevealCalldata(transactionData, submissionInterface, expected = {}) {
  const raw = String(transactionData).toLowerCase();
  if (!raw.startsWith("0x")) throw new Error("transaction calldata must be 0x-prefixed");
  const hex = raw.slice(2);
  const fragment = submissionInterface.getFunction("reveal");
  const selector = fragment.selector.toLowerCase().slice(2);
  const expectedCommitDaHash = expected.commitDaHash === undefined
    ? null
    : normalizedBytes32(expected.commitDaHash, "expected.commitDaHash");
  const matches = [];
  const decoys = [];
  let cursor = 0;
  while (cursor <= hex.length - selector.length) {
    const index = hex.indexOf(selector, cursor);
    if (index === -1) break;
    cursor = index + 2;
    if (index % 2 !== 0) continue;
    const tail = `0x${hex.slice(index)}`;
    let args;
    try { args = submissionInterface.decodeFunctionData(fragment, tail); }
    catch { continue; }
    const encoded = submissionInterface.encodeFunctionData(fragment, args).toLowerCase();
    if (!tail.startsWith(encoded)) continue;
    const [submissionId, solutionCid, claimedScoreAtoms, improvementAtoms, salt, solution] = args;
    if (expected.submissionId !== undefined && BigInt(submissionId) !== BigInt(expected.submissionId)) continue;
    if (expected.solutionCid !== undefined && solutionCid !== expected.solutionCid) continue;
    if (expected.claimedScoreAtoms !== undefined && BigInt(claimedScoreAtoms) !== BigInt(expected.claimedScoreAtoms)) continue;
    if (expected.improvementAtoms !== undefined && BigInt(improvementAtoms) !== BigInt(expected.improvementAtoms)) continue;
    const solutionBytesLength = (String(solution).length - 2) / 2;
    if (expected.solutionBytesLength !== undefined && solutionBytesLength !== Number(expected.solutionBytesLength)) continue;
    const recovered = {
      submissionId: BigInt(submissionId),
      solutionCid,
      claimedScoreAtoms: BigInt(claimedScoreAtoms),
      improvementAtoms: BigInt(improvementAtoms),
      salt,
      solution,
      solutionBytesLength,
      calldataOffsetBytes: index / 2,
      nested: index !== 0,
      callData: encoded,
    };
    if (expectedCommitDaHash !== null) {
      recovered.commitDaHash = ethers.sha256(solution).toLowerCase();
      if (recovered.commitDaHash !== expectedCommitDaHash) {
        decoys.push(recovered);
        continue;
      }
    }
    matches.push(recovered);
  }
  if (matches.length === 1 && decoys.length === 0) return matches[0];
  if (matches.length > 1) {
    throw new Error(`ambiguous reveal calldata: ${matches.length} candidates matched the Revealed log and commitDaHash`);
  }
  if (decoys.length > 0) {
    throw new Error("reveal calldata decoy matched the Revealed log but not commitDaHash");
  }
  throw new Error("no reveal calldata matched the Revealed log context");
}

export function submissionIdFromCommittedReceipt(receipt, submissionInterface, expectedSolver, submissionAddress) {
  const matches = [];
  for (const log of receipt?.logs || []) {
    if (submissionAddress && String(log.address).toLowerCase() !== String(submissionAddress).toLowerCase()) continue;
    let parsed;
    try { parsed = submissionInterface.parseLog(log); }
    catch { continue; }
    if (!parsed || parsed.name !== "Committed") continue;
    if (expectedSolver && String(parsed.args.solver).toLowerCase() !== String(expectedSolver).toLowerCase()) continue;
    matches.push(BigInt(parsed.args.submissionId));
  }
  if (matches.length !== 1) {
    throw new Error(`expected exactly one matching Committed log, found ${matches.length}`);
  }
  return matches[0];
}

export function solverLifecycleDecision(snapshot) {
  const status = Number(snapshot.status);
  const now = BigInt(snapshot.now ?? 0);
  if (status === 1) return { action: "reveal" };
  if (status === 2) {
    const challengeEndsAt = BigInt(snapshot.challengeEndsAt ?? 0);
    if (now < challengeEndsAt) return { action: "wait_challenge_window", wakeAt: challengeEndsAt };
    const shortfall = BigInt(snapshot.bondShortfallWei ?? 0);
    if (shortfall > 0n) return { action: "top_up_bond", valueWei: shortfall };
    return { action: "finalize" };
  }
  if (status === 3) {
    if (snapshot.decisionPending === true) {
      const releaseAt = BigInt(snapshot.resolverBondReleaseAt ?? 0);
      if (now < releaseAt) return { action: "wait_resolution_finality", wakeAt: releaseAt };
      return { action: "finalize_resolution" };
    }
    const disputeEndsAt = BigInt(snapshot.disputeEndsAt ?? 0);
    if (snapshot.challengeResolved === true) return { action: "refresh_chain_state" };
    if (now < disputeEndsAt) return { action: "wait_resolution", wakeAt: disputeEndsAt };
    return { action: "expire_challenge" };
  }
  if (status === 4) {
    const bond = BigInt(snapshot.bondClaimableWei ?? 0);
    if (bond > 0n) return { action: "claim_bond", valueWei: bond };
    if (snapshot.ledgerClosed !== true) {
      if (snapshot.closeRequested === true && BigInt(snapshot.openSubmissionCount ?? 0) === 0n) {
        return { action: "close" };
      }
      return { action: "wait_close" };
    }
    const payout = BigInt(snapshot.payoutClaimableWei ?? 0);
    if (payout > 0n) return { action: "claim_payout", valueWei: payout };
    return { action: "done" };
  }
  if (status === 5 || status === 6) {
    const bond = BigInt(snapshot.bondClaimableWei ?? 0);
    return bond > 0n ? { action: "claim_bond", valueWei: bond } : { action: "done" };
  }
  return { action: "refresh_chain_state" };
}

export function buildChallengeCallPolicy({
  challengeInterface,
  challengeContract,
  chainId,
  problemId,
  submissionId,
  revealInstanceHash,
  reasonHash,
  candidateHash,
  sourceEventHash,
  expiresAt,
  valueWei,
}) {
  const boundRevealInstanceHash = normalizedBytes32(revealInstanceHash, "revealInstanceHash");
  const calldata = challengeInterface.encodeFunctionData("challenge", [
    submissionId,
    boundRevealInstanceHash,
    reasonHash,
  ]);
  const selector = challengeInterface.getFunction("challenge").selector;
  const target = String(challengeContract).toLowerCase();
  const scope = [
    "p42:challenge:v1",
    `chain:${chainId}`,
    `target:${target}`,
    `problem:${problemId}`,
    `submission:${submissionId}`,
    `reveal:${boundRevealInstanceHash}`,
    `event:${sourceEventHash}`,
    `candidate:${candidateHash}`,
  ].join("|");
  const policy = {
    schema_version: "p42-session-call-policy/v1",
    target,
    selector,
    allowed: true,
    chain_id: Number(chainId),
    expires_at: String(expiresAt),
    max_calls: 1,
    calldata,
    calldata_hash: ethers.keccak256(calldata),
    scope,
    scope_hash: ethers.id(scope),
    call_value_wei: String(valueWei),
    required_per_call_value_cap_wei: String(valueWei),
    candidate_hash: candidateHash,
    set_call_policy: {
      function: "setCallPolicy(address,bytes4,bool,uint256,uint64,uint32,bytes32,bytes32)",
      arguments: [
        target,
        selector,
        true,
        String(chainId),
        String(expiresAt),
        1,
        ethers.keccak256(calldata),
        ethers.id(scope),
      ],
    },
    execute: {
      function: "execute(address,uint256,bytes)",
      arguments: [target, String(valueWei), calldata],
    },
  };
  policy.policy_hash = sha256Canonical(policy);
  return policy;
}

// Direct local-test execution must use the exact same bytes that a production
// P42AgentWallet policy binds. Keeping this adapter here makes ABI drift visible
// in the runtime tests instead of only after talking to a local chain.
export function exactCallRequestFromPolicy(callPolicy, valueWei = callPolicy?.call_value_wei) {
  if (callPolicy?.schema_version !== "p42-session-call-policy/v1") {
    throw new Error("exact call policy has an unsupported schema");
  }
  if (!ethers.isAddress(callPolicy.target) || !ethers.isHexString(callPolicy.calldata)) {
    throw new Error("exact call policy target or calldata is invalid");
  }
  const value = BigInt(valueWei);
  if (value < 0n) throw new Error("exact call policy value must be non-negative");
  if (String(value) !== String(callPolicy.call_value_wei)) {
    throw new Error("exact call policy value does not match the bound call value");
  }
  return { to: ethers.getAddress(callPolicy.target), data: callPolicy.calldata, value };
}

// A receipt is only terminal after its containing block is still canonical and
// has satisfied the configured finality depth. A missing/replaced block means
// the raw signed transaction must return to the journal/rebroadcast path.
export function classifyReceiptFinality({
  receiptBlockNumber,
  receiptBlockHash,
  canonicalBlockHash,
  latestBlockNumber,
  confirmations,
}) {
  const blockNumber = Number(receiptBlockNumber);
  const latest = Number(latestBlockNumber);
  const required = Number(confirmations);
  if (!Number.isInteger(blockNumber) || blockNumber < 0) {
    throw new Error("receipt block number is invalid");
  }
  if (!Number.isInteger(latest) || latest < blockNumber) {
    throw new Error("latest block number is invalid for receipt finality");
  }
  if (!Number.isInteger(required) || required < 0) {
    throw new Error("receipt finality confirmations must be a non-negative integer");
  }
  if (
    !ethers.isHexString(receiptBlockHash, 32)
    || !ethers.isHexString(canonicalBlockHash, 32)
    || receiptBlockHash.toLowerCase() !== canonicalBlockHash.toLowerCase()
  ) {
    return "reorged";
  }
  return latest - blockNumber + 1 >= required ? "confirmed" : "submitted";
}

export const LOCAL_OPERATOR_CHAIN_IDS = new Set([1337, 31337]);

export function resolveOperatorFinality({
  manifest,
  confirmations,
  reorgOverlapBlocks,
  localTest = false,
}) {
  const policy = manifest.indexer?.finalityPolicy ?? {};
  const resolvedConfirmations = confirmations === null || confirmations === undefined
    ? Number(policy.confirmations ?? 0)
    : Number(confirmations);
  const resolvedOverlap = reorgOverlapBlocks === null || reorgOverlapBlocks === undefined
    ? Number(policy.reorgOverlapBlocks ?? 1)
    : Number(reorgOverlapBlocks);
  if (!Number.isInteger(resolvedConfirmations) || resolvedConfirmations < 0) {
    throw new Error("operator confirmations must be a non-negative integer");
  }
  if (!Number.isInteger(resolvedOverlap) || resolvedOverlap < 1) {
    throw new Error("operator reorg overlap must be a positive integer");
  }
  if (!localTest && resolvedConfirmations < 1) {
    throw new Error("production operator requires at least one finality confirmation");
  }
  return { confirmations: resolvedConfirmations, reorgOverlapBlocks: resolvedOverlap };
}

export function validateOperatorExecutionMode({
  manifest,
  chainId,
  localTest = false,
  agentWalletAddress = null,
  operatorAddress = null,
}) {
  const numericChainId = Number(chainId);
  if (localTest) {
    if (!LOCAL_OPERATOR_CHAIN_IDS.has(numericChainId)) {
      throw new Error("direct EOA local-test mode is only allowed on local chain ids 1337 or 31337");
    }
    return { mode: "direct-eoa-local-test", agentWalletAddress: null };
  }
  if (!agentWalletAddress) {
    throw new Error("production operator requires --agent-wallet <P42AgentWallet address>");
  }
  const normalizedAgentWallet = ethers.getAddress(agentWalletAddress).toLowerCase();
  if (operatorAddress && normalizedAgentWallet === ethers.getAddress(operatorAddress).toLowerCase()) {
    throw new Error("agent wallet address must differ from the operator session-key EOA");
  }
  if (manifest.status === "example-not-deployed") {
    throw new Error("production operator cannot run against an example-not-deployed manifest");
  }
  return { mode: "agent-wallet", agentWalletAddress: normalizedAgentWallet };
}

export function operatorCursorBinding({
  manifest,
  chainId,
  submissionContract,
  challengeContract,
  problemId,
}) {
  return {
    schema_version: "p42-operator-binding/v1",
    chain_id: Number(chainId),
    deployment_commit: String(manifest.deploymentCommit ?? "").toLowerCase(),
    deployment_config_hash: String(manifest.deploymentConfigHash ?? "").toLowerCase(),
    submission_contract: String(submissionContract).toLowerCase(),
    challenge_contract: String(challengeContract).toLowerCase(),
    problem_id: String(problemId),
    manifest_start_block: Number(manifest.indexer?.startBlock ?? 0),
  };
}

export function validateOperatorCursor(cursor, binding) {
  if (cursor.schema_version !== "p42-operator-cursor/v1") {
    throw new Error("unsupported operator cursor schema");
  }
  if (canonicalJson(cursor.binding) !== canonicalJson(binding)) {
    throw new Error("operator cursor belongs to a different deployment binding");
  }
  if (!Number.isInteger(cursor.next_block) || cursor.next_block < binding.manifest_start_block) {
    throw new Error("operator cursor next_block is invalid for this manifest");
  }
  if (!Array.isArray(cursor.anchors)) throw new Error("operator cursor anchors must be an array");
  for (const anchor of cursor.anchors) {
    if (!Number.isInteger(anchor.block_number) || anchor.block_number < binding.manifest_start_block) {
      throw new Error("operator cursor anchor block_number is invalid");
    }
    if (!ethers.isHexString(anchor.block_hash, 32)) {
      throw new Error("operator cursor anchor block_hash must be bytes32 hex");
    }
  }
  return cursor;
}

export function nextOperatorScanRange({ cursor, startBlock, safeLatest, overlapBlocks }) {
  if (!Number.isInteger(startBlock) || startBlock < 0) throw new Error("startBlock must be a non-negative integer");
  if (!Number.isInteger(safeLatest) || safeLatest < 0) throw new Error("safeLatest must be a non-negative integer");
  if (!Number.isInteger(overlapBlocks) || overlapBlocks < 1) throw new Error("overlapBlocks must be positive");
  const nextBlock = cursor?.next_block ?? startBlock;
  const fromBlock = Math.max(startBlock, nextBlock - overlapBlocks);
  if (fromBlock > safeLatest) return null;
  return { fromBlock, toBlock: safeLatest };
}

export function buildOperatorCursor({ binding, nextBlock, anchors, overlapBlocks }) {
  if (!Number.isInteger(nextBlock) || nextBlock < binding.manifest_start_block) {
    throw new Error("operator cursor nextBlock is invalid");
  }
  const anchorFloor = Math.max(binding.manifest_start_block, nextBlock - overlapBlocks - 1);
  return {
    schema_version: "p42-operator-cursor/v1",
    binding,
    next_block: nextBlock,
    anchors: [...anchors]
      .filter((anchor) => anchor.block_number >= anchorFloor)
      .sort((left, right) => left.block_number - right.block_number),
    updated_at_utc: new Date().toISOString(),
  };
}

export async function buildSignedTransactionRecord({
  wallet,
  request,
  label,
  chainId = undefined,
}) {
  const populateInput = { ...request, chainId: chainId ?? request.chainId };
  const populated = wallet.provider
    ? await wallet.populateTransaction(populateInput)
    : { from: wallet.address, ...populateInput };
  const signable = { ...populated };
  delete signable.from;
  const rawTx = await wallet.signTransaction(signable);
  const hash = ethers.keccak256(rawTx);
  return {
    schema_version: "p42-signed-transaction/v1",
    label,
    signer: wallet.address.toLowerCase(),
    hash,
    raw_tx: rawTx,
    chain_id: Number(signable.chainId ?? chainId),
    nonce: Number(signable.nonce),
    to: signable.to ? String(signable.to).toLowerCase() : null,
    value: (signable.value ?? 0n).toString(),
    data_hash: ethers.keccak256(signable.data ?? "0x"),
    signed_at_utc: new Date().toISOString(),
  };
}

export async function reconcileSignedTransaction(provider, record) {
  if (record?.schema_version !== "p42-signed-transaction/v1") {
    throw new Error("unsupported signed transaction journal record");
  }
  const receipt = await provider.getTransactionReceipt(record.hash);
  if (receipt) return { status: "receipt", receipt };
  const pending = await provider.getTransaction(record.hash);
  if (pending) return { status: "pending", transaction: pending };
  try {
    return { status: "broadcast", transaction: await provider.broadcastTransaction(record.raw_tx) };
  } catch (error) {
    const after = await provider.getTransaction(record.hash);
    if (after) return { status: "pending", transaction: after };
    throw error;
  }
}

export async function receiptForSignedTransaction(provider, record) {
  const reconciled = await reconcileSignedTransaction(provider, record);
  if (reconciled.receipt) return reconciled.receipt;
  return reconciled.transaction.wait();
}

export function runRuntimeBridge(repoRoot, args) {
  const env = { ...process.env, PYTHONPATH: `${repoRoot}/src` };
  for (const name of Object.keys(env)) {
    if (/(PRIVATE_KEY|API_KEY|TOKEN|SECRET|PASSWORD|RPC_URL)/i.test(name)) delete env[name];
  }
  const completed = spawnSync("python3", [`${repoRoot}/agent/runtime_bridge.py`, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    env,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (completed.error) throw completed.error;
  if (completed.status !== 0) {
    throw new Error((completed.stderr || completed.stdout || `runtime bridge exited ${completed.status}`).trim());
  }
  const output = completed.stdout.trim();
  if (!output) throw new Error("runtime bridge produced no JSON");
  return JSON.parse(output);
}

// Page a queryFilter over small block windows SEQUENTIALLY with retries, so a
// public RPC's getLogs range cap / rate-limit does not fail the whole scan.
// Shared by operator.mjs (fraud policing) and indexer.mjs (reconstruction).
const _sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export async function queryChunked(contract, filter, from, to, step = 2000) {
  const out = [];
  for (let start = from; start <= to; start += step) {
    const end = Math.min(start + step - 1, to);
    let lastErr;
    for (let attempt = 0; attempt < 5; attempt++) {
      try { out.push(...(await contract.queryFilter(filter, start, end))); lastErr = null; break; }
      catch (e) { lastErr = e; await _sleep(1200 * (attempt + 1)); }
    }
    if (lastErr) throw lastErr;
  }
  return out;
}
