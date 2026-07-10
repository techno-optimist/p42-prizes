import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync, readdirSync, renameSync, rmSync, statSync, writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { ethers } from "ethers";
import { assertSignedTransactionRecord } from "./signed-transaction.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";

const JSON_LIMITS = Object.freeze({ maxBytes: 2 * 1024 * 1024, maxDepth: 48 });
const JOURNAL_LIMITS = Object.freeze({ ...JSON_LIMITS, canonicalBytes: true, trailingNewline: "require" });
const DEFAULTS = Object.freeze({
  perChallengeWei: ethers.parseEther("0.05"), perProblemDayWei: ethers.parseEther("0.10"),
  globalDayWei: ethers.parseEther("0.30"), maxCanonicalOpen: 3, maxPendingProvisioned: 1,
});

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

export function utcDay(timestamp = Date.now()) {
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) throw new Error("challenge envelope timestamp is invalid");
  return date.toISOString().slice(0, 10);
}

function emptyState() { return { schema_version: "p42-challenge-envelope-state/v2", days: {} }; }
function dayBucket(state, day) {
  state.days[day] ??= { reservations: {}, spends: {} };
  return state.days[day];
}

function atomicWrite(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  const fd = openSync(temporary, "wx", 0o600);
  try { writeFileSync(fd, `${canonicalJson(value)}\n`); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(temporary, path);
  const directory = openSync(dirname(path), "r");
  try { fsyncSync(directory); } finally { closeSync(directory); }
}

function readState(path) {
  if (!existsSync(path)) return emptyState();
  const state = readStrictJsonFileSync(path, JSON_LIMITS);
  if (state.schema_version !== "p42-challenge-envelope-state/v2" || !state.days || typeof state.days !== "object") {
    throw new Error("unsupported or incomplete challenge envelope state");
  }
  return state;
}

function acquire(lockPath, timeoutMs = 5000) {
  const started = Date.now();
  for (;;) {
    try { mkdirSync(lockPath, { mode: 0o700 }); writeFileSync(`${lockPath}/owner`, `${process.pid}\n`, { flag: "wx", mode: 0o600 }); return; }
    catch (error) {
      if (error.code !== "EEXIST") throw error;
      try { if (Date.now() - statSync(lockPath).mtimeMs > 60_000) { rmSync(lockPath, { recursive: true }); continue; } }
      catch (statError) { if (statError.code !== "ENOENT") throw statError; }
      if (Date.now() - started >= timeoutMs) throw new Error("challenge envelope lock timeout");
    }
  }
}

export function withEnvelopeLock(statePath, operation, { now = Date.now(), timeoutMs = 5000 } = {}) {
  const path = resolve(statePath); const lock = `${path}.lock`;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); acquire(lock, timeoutMs);
  try { const state = readState(path); const result = operation(state, utcDay(now)); atomicWrite(path, state); return result; }
  finally { rmSync(lock, { recursive: true, force: true }); }
}

function artifactPreimage(value) {
  const copy = structuredClone(value); delete copy.artifact_hash; delete copy.signature;
  return canonicalJson(copy);
}

export function validateProvisioningArtifact(value, expected = {}) {
  if (value?.schema_version !== "p42-challenge-provisioning/v1") throw new Error("unsupported provisioning artifact");
  if (!Number.isSafeInteger(value.chain_id) || value.chain_id < 1) throw new Error("provisioning chain_id is invalid");
  for (const field of ["challenge_manager", "agent_wallet", "operator"]) {
    if (!ethers.isAddress(value[field]) || value[field] === ethers.ZeroAddress) throw new Error(`provisioning ${field} is invalid`);
  }
  if (expected.chainId !== undefined && value.chain_id !== Number(expected.chainId)) throw new Error("provisioning chain mismatch");
  if (expected.challengeManager && ethers.getAddress(value.challenge_manager) !== ethers.getAddress(expected.challengeManager)) throw new Error("provisioning challenge manager mismatch");
  if (expected.agentWallet && ethers.getAddress(value.agent_wallet) !== ethers.getAddress(expected.agentWallet)) throw new Error("provisioning agent wallet mismatch");
  if (expected.operator && ethers.getAddress(value.operator) !== ethers.getAddress(expected.operator)) throw new Error("provisioning operator mismatch");
  const exact = [
    ["per_challenge_wei", DEFAULTS.perChallengeWei], ["per_problem_day_wei", DEFAULTS.perProblemDayWei],
    ["global_day_wei", DEFAULTS.globalDayWei], ["max_canonical_open", 3n], ["max_pending_provisioned", 1n],
  ];
  for (const [field, wanted] of exact) { try { if (BigInt(value[field]) !== wanted) throw new Error(); } catch { throw new Error(`provisioning ${field} default mismatch`); } }
  if (value.rehearsal?.health_gate_verified !== true || value.rehearsal?.restart_recovery_verified !== true || value.rehearsal?.deep_reorg_verified !== true) throw new Error("rehearsal evidence incomplete");
  if (!/^sha256:[a-f0-9]{64}$/.test(value.rehearsal?.artifact_hash ?? "")) throw new Error("rehearsal artifact hash is invalid");
  const digest = `sha256:${ethers.sha256(ethers.toUtf8Bytes(artifactPreimage(value))).slice(2)}`;
  if (value.artifact_hash !== digest) throw new Error("provisioning artifact hash mismatch");
  if (value.signature?.scheme !== "eip191" || !ethers.isAddress(value.signature.signer) || !ethers.isHexString(value.signature.signature, 65)) throw new Error("provisioning signature is invalid");
  let recovered;
  try { recovered = ethers.verifyMessage(value.artifact_hash, value.signature.signature); }
  catch { throw new Error("provisioning signature verification failed"); }
  if (recovered !== ethers.getAddress(value.signature.signer)) throw new Error("provisioning signature verification failed");
  if (ethers.getAddress(value.signature.signer) !== ethers.getAddress(value.operator)) throw new Error("provisioning signature signer is not operator");
  return value;
}

export function limitsFromProvisioning(provisioning, tightened = {}) {
  validateProvisioningArtifact(provisioning);
  const base = {
    perChallengeWei: BigInt(provisioning.per_challenge_wei), perProblemDayWei: BigInt(provisioning.per_problem_day_wei),
    globalDayWei: BigInt(provisioning.global_day_wei), maxCanonicalOpen: Number(provisioning.max_canonical_open),
    maxPendingProvisioned: Number(provisioning.max_pending_provisioned),
  };
  const result = { ...base };
  for (const [key, raw] of Object.entries(tightened)) {
    if (!(key in base)) throw new Error(`unknown tightened challenge limit ${key}`);
    const value = typeof base[key] === "bigint" ? BigInt(raw) : Number(raw);
    if (value <= 0 || value > base[key]) throw new Error(`challenge limit ${key} may only tighten provisioning`);
    result[key] = value;
  }
  return Object.freeze(result);
}

export function runnerHealthAdmission(health, { now = Date.now(), maxAgeMs = 300_000 } = {}) {
  const observed = Date.parse(health?.observed_at_utc);
  const complete = health?.schema_version === "p42-runner-health/v1" && Number.isFinite(observed)
    && observed <= now && now - observed <= maxAgeMs && health.oom_kills === 0 && health.worker_restarts === 0
    && health.queue_corruption_events === 0 && health.max_active_running === 1 && health.decision === "start"
    && health.swap_guard === "green" && health.host_capacity === "green" && health.concurrency_guard === "green";
  return { allowed: complete, reason: complete ? "green" : "runner_health_fail_closed" };
}

export function validateCanonicalOpenEvidence(evidence, { chainId, challengeManager, finalizedThroughBlock, maxAgeMs = 300_000, now = Date.now() } = {}) {
  const observed = Date.parse(evidence?.observed_at_utc);
  if (evidence?.schema_version !== "p42-canonical-open-evidence/v1" || evidence.complete !== true || !Number.isFinite(observed) || observed > now || now - observed > maxAgeMs) throw new Error("canonical open evidence is missing, stale, future, or incomplete");
  if (Number(evidence.chain_id) !== Number(chainId) || ethers.getAddress(evidence.challenge_manager) !== ethers.getAddress(challengeManager)) throw new Error("canonical open evidence binding mismatch");
  if (!Number.isSafeInteger(evidence.finalized_through_block) || evidence.finalized_through_block < Number(finalizedThroughBlock)) throw new Error("canonical open evidence is not finalized through required block");
  if (!Array.isArray(evidence.open_challenges) || evidence.open_challenges.some((row) => !/^[1-9][0-9]*$/.test(row.submission_id) || !ethers.isHexString(row.challenge_instance_hash, 32))) throw new Error("canonical open evidence rows are invalid");
  if (new Set(evidence.open_challenges.map((row) => row.submission_id)).size !== evidence.open_challenges.length) throw new Error("canonical open evidence contains duplicates");
  return evidence;
}

export function reserveChallengeSpend(statePath, input, options = {}) {
  if (input.limits !== undefined) throw new Error("public challenge limit overrides are forbidden");
  const limits = limitsFromProvisioning(input.provisioning, input.tightenedLimits);
  const amount = BigInt(input.amountWei);
  if (!input.id || !input.problemId) throw new Error("challenge reservation identity is required");
  if (!runnerHealthAdmission(input.health, { now: options.now ?? Date.now() }).allowed) throw new Error("auto-file disabled: runner health is not green");
  const evidence = validateCanonicalOpenEvidence(input.canonicalOpenEvidence, input.canonicalEvidenceExpected);
  if (evidence.open_challenges.length >= limits.maxCanonicalOpen) throw new Error("canonical open challenge cap reached");
  if (amount <= 0n || amount > limits.perChallengeWei) throw new Error("per-challenge spend cap exceeded");
  return withEnvelopeLock(statePath, (state, day) => {
    for (const [bucketDay, bucket] of Object.entries(state.days)) {
      if (bucket.reservations?.[input.id] || bucket.spends?.[input.id]) return { reserved: false, idempotent: true, day: bucketDay };
    }
    const pending = Object.values(state.days).flatMap((bucket) => Object.values(bucket.reservations ?? {}));
    if (pending.length >= limits.maxPendingProvisioned) throw new Error("one exact challenge policy is already pending");
    const bucket = dayBucket(state, day); const rows = [...Object.values(bucket.reservations), ...Object.values(bucket.spends)];
    const global = rows.reduce((sum, row) => sum + BigInt(row.amount_wei), 0n);
    const problem = rows.filter((row) => row.problem_id === input.problemId).reduce((sum, row) => sum + BigInt(row.amount_wei), 0n);
    if (problem + amount > limits.perProblemDayWei) throw new Error("per-problem UTC-day spend cap exceeded");
    if (global + amount > limits.globalDayWei) throw new Error("global UTC-day spend cap exceeded");
    bucket.reservations[input.id] = { problem_id: input.problemId, amount_wei: amount.toString(), reserved_at_utc: new Date(options.now ?? Date.now()).toISOString() };
    return { reserved: true, idempotent: false, day };
  }, options);
}

export function finalizeChallengeSpend(statePath, id, { finalizedReceipt, ...options } = {}) {
  if (!finalizedReceipt?.canonical || !Number.isSafeInteger(finalizedReceipt.block_number) || !ethers.isHexString(finalizedReceipt.block_hash, 32)) throw new Error("finalized canonical challenge receipt evidence is required");
  return withEnvelopeLock(statePath, (state) => {
    for (const bucket of Object.values(state.days)) {
      if (bucket.spends?.[id]) return { committed: true, idempotent: true };
      const reservation = bucket.reservations?.[id];
      if (!reservation) continue;
      bucket.spends[id] = { ...reservation, transaction_hash: finalizedReceipt.transaction_hash, block_number: finalizedReceipt.block_number, block_hash: finalizedReceipt.block_hash.toLowerCase() };
      delete bucket.reservations[id]; return { committed: true, idempotent: false };
    }
    throw new Error("finalized challenge has no durable reservation");
  }, options);
}

export function releaseChallengeReservation(statePath, id, options = {}) {
  return withEnvelopeLock(statePath, (state) => {
    for (const bucket of Object.values(state.days)) if (bucket.reservations && delete bucket.reservations[id]) return { released: true };
    return { released: false };
  }, options);
}

export function buildClaimBondPolicy({ challengeInterface, challengeContract, chainId, claimant, expiresAt }) {
  const calldata = challengeInterface.encodeFunctionData("claimBond");
  const scope = { action: "claimBond", chain_id: Number(chainId), target: challengeContract.toLowerCase(), claimant: claimant.toLowerCase() };
  return { schema_version: "p42-session-call-policy/v1", target: challengeContract.toLowerCase(), selector: calldata.slice(0, 10), calldata, calldata_hash: ethers.keccak256(calldata), scope, scope_hash: ethers.keccak256(ethers.toUtf8Bytes(canonicalJson(scope))), call_value_wei: "0", expires_at: String(expiresAt), max_calls: 1 };
}

export function claimedBondAmountFromReceipt({ receipt, challengeInterface, challengeContract, claimant }) {
  if (receipt?.status !== 1) throw new Error("successful claim receipt required");
  const matches = [];
  for (const log of receipt.logs ?? []) {
    if (String(log.address).toLowerCase() !== String(challengeContract).toLowerCase()) continue;
    try { const parsed = challengeInterface.parseLog(log); if (parsed?.name === "BondClaimed" && String(parsed.args.claimant).toLowerCase() === String(claimant).toLowerCase()) matches.push(BigInt(parsed.args.amount)); } catch {}
  }
  if (matches.length !== 1 || matches[0] <= 0n) throw new Error("claim receipt must contain exactly one positive BondClaimed event for claimant");
  return matches[0];
}

export function reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash, latestBlockNumber, confirmations, challengeInterface, challengeContract, claimant }) {
  if (journal?.schema_version !== "p42-claim-bond-action/v1") throw new Error("invalid claim-bond journal");
  if (!receipt) return { status: "rebroadcast", recovered_wei: "0" };
  if (!canonicalBlockHash || canonicalBlockHash.toLowerCase() !== receipt.blockHash.toLowerCase()) return { status: "reorged", recovered_wei: "0" };
  if (latestBlockNumber - receipt.blockNumber + 1 < confirmations) return { status: "submitted", recovered_wei: "0" };
  if (receipt.status !== 1) return { status: "broadcast_reverted", recovered_wei: "0" };
  return { status: "confirmed", recovered_wei: claimedBondAmountFromReceipt({ receipt, challengeInterface, challengeContract, claimant }).toString() };
}

export class P42ChallengeManager {
  constructor({ provider, wallet, agentWallet, challenge, chainId, journalPath, confirmations = 1, now = () => Date.now() }) { Object.assign(this, { provider, wallet, agentWallet, challenge, chainId, journalPath, confirmations, now }); }
  async assertClaimPolicy(policy, latestTimestamp) {
    const onchain = await this.agentWallet.callPolicies(policy.target, policy.selector);
    if (await this.agentWallet.sessionKey().then((v) => v.toLowerCase()) !== this.wallet.address.toLowerCase()) throw new Error("claim policy session key mismatch");
    if (Number(await this.agentWallet.sessionChainId()) !== this.chainId || await this.agentWallet.revoked()) throw new Error("claim policy session invalid");
    if (!await this.agentWallet.allowed(policy.target, policy.selector) || !onchain.configured || Number(onchain.chainId) !== this.chainId || Number(onchain.maxCalls) !== 1 || Number(onchain.calls) !== 0) throw new Error("claimBond exact policy is unavailable");
    if (BigInt(onchain.expiresAt) <= BigInt(latestTimestamp) || String(onchain.calldataHash).toLowerCase() !== policy.calldata_hash.toLowerCase() || String(onchain.scopeHash).toLowerCase() !== policy.scope_hash.toLowerCase()) throw new Error("claimBond exact policy mismatch");
  }
  async claimBond() {
    const claimant = (await this.agentWallet.getAddress()).toLowerCase();
    const archivePrefix = `${basename(this.journalPath)}.`;
    for (const name of readdirSync(dirname(this.journalPath)).filter((entry) => entry.startsWith(archivePrefix) && entry.endsWith(".confirmed"))) {
      const path = join(dirname(this.journalPath), name);
      const archived = readStrictJsonFileSync(path, JOURNAL_LIMITS);
      const receipt = await this.provider.getTransactionReceipt(archived.signed_tx.hash);
      const canonical = receipt ? await this.provider.getBlock(receipt.blockNumber) : null;
      const audit = reconcileClaimLifecycle({ journal: archived, receipt, canonicalBlockHash: canonical?.hash, latestBlockNumber: await this.provider.getBlockNumber(), confirmations: this.confirmations, challengeInterface: this.challenge.interface, challengeContract: await this.challenge.getAddress(), claimant });
      if (audit.status !== "confirmed") {
        archived.status = audit.status; archived.recovered_wei = "0"; atomicWrite(path, archived);
        throw new Error(`archived claim journal lost canonical finality: ${name}`);
      }
    }
    let journal = existsSync(this.journalPath) ? readStrictJsonFileSync(this.journalPath, JOURNAL_LIMITS) : null;
    if (journal?.status === "confirmed") {
      const receipt = await this.provider.getTransactionReceipt(journal.signed_tx.hash);
      const canonical = receipt ? await this.provider.getBlock(receipt.blockNumber) : null;
      const audit = reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash: canonical?.hash, latestBlockNumber: await this.provider.getBlockNumber(), confirmations: this.confirmations, challengeInterface: this.challenge.interface, challengeContract: await this.challenge.getAddress(), claimant });
      if (audit.status !== "confirmed") { journal.status = audit.status; journal.recovered_wei = "0"; atomicWrite(this.journalPath, journal); return audit; }
      const next = BigInt(await this.challenge.claimableBondWei(claimant)); if (next === 0n) return { status: "nothing_claimable", recovered_wei: "0" };
      renameSync(this.journalPath, `${this.journalPath}.${journal.signed_tx.hash.slice(2, 18)}.confirmed`); journal = null;
    }
    if (!journal) {
      const claimable = BigInt(await this.challenge.claimableBondWei(claimant)); if (claimable === 0n) return { status: "nothing_claimable", recovered_wei: "0" };
      const latest = await this.provider.getBlock("latest"); const policy = buildClaimBondPolicy({ challengeInterface: this.challenge.interface, challengeContract: await this.challenge.getAddress(), chainId: this.chainId, claimant, expiresAt: BigInt(latest.timestamp) + 3600n });
      await this.assertClaimPolicy(policy, latest.timestamp); const request = await this.agentWallet.execute.populateTransaction(policy.target, 0n, policy.calldata); const populated = await this.wallet.populateTransaction(request); const signable = { ...populated }; delete signable.from; const rawTx = await this.wallet.signTransaction(signable);
      journal = { schema_version: "p42-claim-bond-action/v1", status: "signed", policy, signed_tx: { schema_version: "p42-signed-transaction/v1", label: "claimBond", signer: this.wallet.address.toLowerCase(), hash: ethers.keccak256(rawTx), raw_tx: rawTx, chain_id: this.chainId, nonce: Number(signable.nonce), to: String(signable.to).toLowerCase(), value: "0", data_hash: ethers.keccak256(signable.data), signed_at_utc: new Date(this.now()).toISOString() }, recovered_wei: "0" }; atomicWrite(this.journalPath, journal);
    }
    const expectedData = this.agentWallet.interface.encodeFunctionData("execute", [journal.policy.target, 0n, journal.policy.calldata]); assertSignedTransactionRecord(journal.signed_tx, { signer: this.wallet.address, chainId: this.chainId, to: await this.agentWallet.getAddress(), value: 0n, data: expectedData, label: "claimBond" });
    let receipt = await this.provider.getTransactionReceipt(journal.signed_tx.hash);
    if (!receipt) { let pending = await this.provider.getTransaction(journal.signed_tx.hash); if (!pending) pending = await this.provider.broadcastTransaction(journal.signed_tx.raw_tx); journal.status = "broadcast"; journal.recovered_wei = "0"; atomicWrite(this.journalPath, journal); receipt = await pending.wait(); }
    const canonical = await this.provider.getBlock(receipt.blockNumber); const result = reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash: canonical?.hash, latestBlockNumber: await this.provider.getBlockNumber(), confirmations: this.confirmations, challengeInterface: this.challenge.interface, challengeContract: await this.challenge.getAddress(), claimant });
    journal.status = result.status; journal.recovered_wei = result.recovered_wei; journal.receipt = { transaction_hash: receipt.hash ?? journal.signed_tx.hash, block_number: receipt.blockNumber, block_hash: receipt.blockHash }; atomicWrite(this.journalPath, journal); return result;
  }
}
