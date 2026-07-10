import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync, renameSync,
  rmSync, statSync, writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { ethers } from "ethers";
import { assertSignedTransactionRecord } from "./signed-transaction.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";

const ACCOUNTING_JSON_LIMITS = Object.freeze({ maxBytes: 2 * 1024 * 1024, maxDepth: 48 });
const JOURNAL_JSON_LIMITS = Object.freeze({ ...ACCOUNTING_JSON_LIMITS, canonicalBytes: true, trailingNewline: "require" });

export const DEFAULT_CHALLENGE_LIMITS = Object.freeze({
  perChallengeWei: ethers.parseEther("0.05"),
  perProblemDayWei: ethers.parseEther("0.10"),
  globalDayWei: ethers.parseEther("0.30"),
  maxCanonicalOpen: 3,
  maxPendingProvisioned: 1,
});

export function utcDay(timestamp = Date.now()) {
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) throw new Error("challenge envelope timestamp is invalid");
  return date.toISOString().slice(0, 10);
}

function emptyState(day) {
  return { schema_version: "p42-challenge-envelope-state/v1", utc_day: day, reservations: {}, spends: {}, open: {} };
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function atomicWrite(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  const fd = openSync(temporary, "wx", 0o600);
  try {
    writeFileSync(fd, `${canonicalJson(value)}\n`);
    fsyncSync(fd);
  } finally { closeSync(fd); }
  renameSync(temporary, path);
  const directory = openSync(dirname(path), "r");
  try { fsyncSync(directory); } finally { closeSync(directory); }
}

function readState(path, day) {
  if (!existsSync(path)) return emptyState(day);
  const state = readStrictJsonFileSync(path, ACCOUNTING_JSON_LIMITS);
  if (state.schema_version !== "p42-challenge-envelope-state/v1") throw new Error("unsupported challenge envelope state");
  if (state.utc_day !== day) return { ...emptyState(day), open: state.open ?? {} };
  return state;
}

function acquire(lockPath, timeoutMs = 5000) {
  const started = Date.now();
  for (;;) {
    try {
      mkdirSync(lockPath, { mode: 0o700 });
      writeFileSync(`${lockPath}/owner`, `${process.pid}\n`, { flag: "wx", mode: 0o600 });
      return;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > 60_000) { rmSync(lockPath, { recursive: true }); continue; }
      } catch (statError) { if (statError.code !== "ENOENT") throw statError; }
      if (Date.now() - started >= timeoutMs) throw new Error("challenge envelope lock timeout");
    }
  }
}

export function withEnvelopeLock(statePath, operation, { now = Date.now(), timeoutMs = 5000 } = {}) {
  const path = resolve(statePath);
  const lock = `${path}.lock`;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  acquire(lock, timeoutMs);
  try {
    const day = utcDay(now);
    const state = readState(path, day);
    const result = operation(state, day);
    atomicWrite(path, state);
    return result;
  } finally { rmSync(lock, { recursive: true, force: true }); }
}

export function runnerHealthAdmission(health) {
  const green = health?.oom_kills === 0 && health?.worker_restarts === 0
    && health?.queue_corruption_events === 0 && health?.max_active_running === 1
    && health?.decision !== "wait" && health?.swap_guard !== "red"
    && health?.host_capacity !== "red" && health?.concurrency_guard !== "red";
  return { allowed: green, reason: green ? "green" : "runner_health_fail_closed" };
}

export function reserveChallengeSpend(statePath, input, options = {}) {
  const limits = { ...DEFAULT_CHALLENGE_LIMITS, ...(input.limits ?? {}) };
  const amount = BigInt(input.amountWei);
  if (!input.id || !input.problemId) throw new Error("challenge reservation identity is required");
  if (!runnerHealthAdmission(input.health).allowed) throw new Error("auto-file disabled: runner health is not green");
  if (amount <= 0n || amount > limits.perChallengeWei) throw new Error("per-challenge spend cap exceeded");
  return withEnvelopeLock(statePath, (state, day) => {
    if (state.reservations[input.id] || state.spends[input.id]) return { reserved: false, idempotent: true, day };
    const pending = Object.keys(state.reservations).length;
    if (pending >= limits.maxPendingProvisioned) throw new Error("one exact challenge policy is already pending");
    if (Object.keys(state.open).length >= limits.maxCanonicalOpen) throw new Error("canonical open challenge cap reached");
    const rows = [...Object.values(state.reservations), ...Object.values(state.spends)];
    const global = rows.reduce((sum, row) => sum + BigInt(row.amount_wei), 0n);
    const problem = rows.filter((row) => row.problem_id === input.problemId)
      .reduce((sum, row) => sum + BigInt(row.amount_wei), 0n);
    if (problem + amount > limits.perProblemDayWei) throw new Error("per-problem UTC-day spend cap exceeded");
    if (global + amount > limits.globalDayWei) throw new Error("global UTC-day spend cap exceeded");
    state.reservations[input.id] = { problem_id: input.problemId, amount_wei: amount.toString(), reserved_at_utc: new Date(options.now ?? Date.now()).toISOString() };
    return { reserved: true, idempotent: false, day };
  }, options);
}

export function finalizeChallengeSpend(statePath, id, { canonicalOpenId = id, ...options } = {}) {
  return withEnvelopeLock(statePath, (state) => {
    const reservation = state.reservations[id];
    if (!reservation) return { committed: Boolean(state.spends[id]), idempotent: true };
    state.spends[id] = reservation;
    state.open[canonicalOpenId] = { reservation_id: id, problem_id: reservation.problem_id };
    delete state.reservations[id];
    return { committed: true, idempotent: false };
  }, options);
}

export function releaseChallengeReservation(statePath, id, options = {}) {
  return withEnvelopeLock(statePath, (state) => ({ released: delete state.reservations[id] }), options);
}

export function closeCanonicalChallenge(statePath, id, options = {}) {
  return withEnvelopeLock(statePath, (state) => ({ closed: delete state.open[id] }), options);
}

export function buildClaimBondPolicy({ challengeInterface, challengeContract, chainId, claimant, expiresAt }) {
  const calldata = challengeInterface.encodeFunctionData("claimBond");
  const scope = { action: "claimBond", chain_id: Number(chainId), target: challengeContract.toLowerCase(), claimant: claimant.toLowerCase() };
  return {
    schema_version: "p42-session-call-policy/v1", target: challengeContract.toLowerCase(), selector: calldata.slice(0, 10),
    calldata, calldata_hash: ethers.keccak256(calldata), scope, scope_hash: ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(scope))),
    call_value_wei: "0", expires_at: String(expiresAt), max_calls: 1,
  };
}

export function reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash, latestBlockNumber, confirmations, claimableWei }) {
  if (journal?.schema_version !== "p42-claim-bond-action/v1") throw new Error("invalid claim-bond journal");
  if (receipt) {
    if (!canonicalBlockHash || canonicalBlockHash.toLowerCase() !== receipt.blockHash.toLowerCase()) return { status: "reorged", recovered_wei: "0" };
    if (latestBlockNumber - receipt.blockNumber + 1 < confirmations) return { status: "submitted", recovered_wei: "0" };
    return receipt.status === 1
      ? { status: "confirmed", recovered_wei: journal.expected_claimable_wei }
      : { status: "broadcast_reverted", recovered_wei: "0" };
  }
  if (BigInt(claimableWei ?? 0) === 0n && journal.status === "confirmed") return { status: "confirmed", recovered_wei: journal.expected_claimable_wei };
  return { status: "rebroadcast", recovered_wei: "0" };
}

export function validateProvisioningArtifact(value) {
  if (value?.schema_version !== "p42-challenge-provisioning/v1") throw new Error("unsupported provisioning artifact");
  if (value.per_challenge_wei !== ethers.parseEther("0.05").toString()) throw new Error("per-challenge default mismatch");
  if (value.per_problem_day_wei !== ethers.parseEther("0.10").toString()) throw new Error("per-problem default mismatch");
  if (value.global_day_wei !== ethers.parseEther("0.30").toString()) throw new Error("global default mismatch");
  if (value.max_canonical_open !== 3 || value.max_pending_provisioned !== 1) throw new Error("challenge concurrency policy mismatch");
  if (value.rehearsal?.health_gate_verified !== true || value.rehearsal?.restart_recovery_verified !== true) throw new Error("rehearsal evidence incomplete");
  return value;
}

export class P42ChallengeManager {
  constructor({ provider, wallet, agentWallet, challenge, chainId, journalPath, confirmations = 1, now = () => Date.now() }) {
    Object.assign(this, { provider, wallet, agentWallet, challenge, chainId, journalPath, confirmations, now });
  }

  async assertClaimPolicy(policy, latestTimestamp) {
    const onchain = await this.agentWallet.callPolicies(policy.target, policy.selector);
    if (await this.agentWallet.sessionKey().then((v) => v.toLowerCase()) !== this.wallet.address.toLowerCase()) throw new Error("claim policy session key mismatch");
    if (Number(await this.agentWallet.sessionChainId()) !== this.chainId) throw new Error("claim policy chain mismatch");
    if (await this.agentWallet.revoked()) throw new Error("claim policy session revoked");
    if (!await this.agentWallet.allowed(policy.target, policy.selector)) throw new Error("claimBond selector is not allowed");
    if (!onchain.configured || Number(onchain.chainId) !== this.chainId || Number(onchain.maxCalls) !== 1 || Number(onchain.calls) !== 0) throw new Error("claimBond exact policy is unavailable");
    if (BigInt(onchain.expiresAt) <= BigInt(latestTimestamp)) throw new Error("claimBond exact policy expired");
    if (String(onchain.calldataHash).toLowerCase() !== policy.calldata_hash.toLowerCase()) throw new Error("claimBond calldata policy mismatch");
    if (String(onchain.scopeHash).toLowerCase() !== policy.scope_hash.toLowerCase()) throw new Error("claimBond scope policy mismatch");
  }

  async claimBond() {
    const claimant = (await this.agentWallet.getAddress()).toLowerCase();
    let journal = existsSync(this.journalPath) ? readStrictJsonFileSync(this.journalPath, JOURNAL_JSON_LIMITS) : null;
    if (journal?.status === "confirmed") {
      const nextClaimable = BigInt(await this.challenge.claimableBondWei(claimant));
      if (nextClaimable === 0n) return { status: "nothing_claimable", recovered_wei: "0" };
      renameSync(this.journalPath, `${this.journalPath}.${journal.signed_tx.hash.slice(2, 18)}.confirmed`);
      journal = null;
    }
    if (!journal) {
      const claimable = BigInt(await this.challenge.claimableBondWei(claimant));
      if (claimable === 0n) return { status: "nothing_claimable", recovered_wei: "0" };
      const latest = await this.provider.getBlock("latest");
      const policy = buildClaimBondPolicy({ challengeInterface: this.challenge.interface, challengeContract: await this.challenge.getAddress(), chainId: this.chainId, claimant, expiresAt: BigInt(latest.timestamp) + 3600n });
      await this.assertClaimPolicy(policy, latest.timestamp);
      const request = await this.agentWallet.execute.populateTransaction(policy.target, 0n, policy.calldata);
      const populated = await this.wallet.populateTransaction(request);
      const signable = { ...populated }; delete signable.from;
      const rawTx = await this.wallet.signTransaction(signable);
      journal = {
        schema_version: "p42-claim-bond-action/v1", status: "signed", expected_claimable_wei: claimable.toString(),
        policy, signed_tx: { schema_version: "p42-signed-transaction/v1", label: "claimBond", signer: this.wallet.address.toLowerCase(), hash: ethers.keccak256(rawTx), raw_tx: rawTx, chain_id: this.chainId, nonce: Number(signable.nonce), to: String(signable.to).toLowerCase(), value: "0", data_hash: ethers.keccak256(signable.data), signed_at_utc: new Date(this.now()).toISOString() },
        recovered_wei: "0",
      };
      atomicWrite(this.journalPath, journal);
    }
    const expectedData = this.agentWallet.interface.encodeFunctionData("execute", [journal.policy.target, 0n, journal.policy.calldata]);
    assertSignedTransactionRecord(journal.signed_tx, { signer: this.wallet.address, chainId: this.chainId, to: await this.agentWallet.getAddress(), value: 0n, data: expectedData, label: "claimBond" });
    let receipt = await this.provider.getTransactionReceipt(journal.signed_tx.hash);
    if (!receipt) {
      let pending = await this.provider.getTransaction(journal.signed_tx.hash);
      if (!pending) pending = await this.provider.broadcastTransaction(journal.signed_tx.raw_tx);
      journal.status = "broadcast"; atomicWrite(this.journalPath, journal);
      receipt = await pending.wait();
    }
    const canonical = await this.provider.getBlock(receipt.blockNumber);
    const result = reconcileClaimLifecycle({ journal, receipt, canonicalBlockHash: canonical?.hash, latestBlockNumber: await this.provider.getBlockNumber(), confirmations: this.confirmations });
    journal.status = result.status;
    journal.recovered_wei = result.recovered_wei;
    journal.receipt = { transaction_hash: receipt.hash ?? journal.signed_tx.hash, block_number: receipt.blockNumber, block_hash: receipt.blockHash };
    atomicWrite(this.journalPath, journal);
    return result;
  }
}
