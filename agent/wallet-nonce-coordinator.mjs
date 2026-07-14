import { ethers } from "ethers";
import {
  closeSync, existsSync, fsyncSync, openSync, renameSync, writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";

import { acquireEnvelopeLock, releaseEnvelopeLock } from "./challenge-envelope.mjs";
import { canonicalJson, sha256Canonical } from "./lib.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";

const LIMITS = {
  maxBytes: 4 * 1024 * 1024,
  maxDepth: 64,
  canonicalBytes: true,
  trailingNewline: "require",
};

export function walletActionLockPath({ coordinationRoot, boundChainId, signer }) {
  if (!Number.isSafeInteger(boundChainId) || boundChainId <= 0) {
    throw new Error("wallet action lock chain id must be a positive safe integer");
  }
  if (!coordinationRoot) throw new Error("wallet action lock coordination root is required");
  const lockId = sha256Canonical({
    schema_version: "p42-wallet-action-lock/v1",
    chain_id: boundChainId,
    signer: ethers.getAddress(signer).toLowerCase(),
  });
  return join(resolve(coordinationRoot), `${lockId.slice(7)}.wallet.lock`);
}

export function walletNonceAllocatorPath(args) {
  return walletActionLockPath(args).replace(/\.wallet\.lock$/, ".nonce-allocator.json");
}

function binding(boundChainId, signer) {
  return {
    schema_version: "p42-wallet-nonce-binding/v1",
    chain_id: boundChainId,
    signer: ethers.getAddress(signer).toLowerCase(),
  };
}

function durableReplaceCanonical(path, value) {
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  const fd = openSync(temporary, "wx", 0o600);
  try {
    writeFileSync(fd, `${canonicalJson(value)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temporary, path);
  const directoryFd = openSync(dirname(path), "r");
  try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
}

function validateJournal(journal, expectedBinding) {
  if (!journal || journal.schema_version !== "p42-wallet-nonce-allocator/v1"
      || canonicalJson(journal.binding) !== canonicalJson(expectedBinding)) {
    throw new Error("wallet nonce allocator journal identity is invalid");
  }
  if (!Number.isSafeInteger(journal.next_nonce) || journal.next_nonce < 0
      || !Number.isSafeInteger(journal.observed_finalized_nonce) || journal.observed_finalized_nonce < 0
      || !Number.isSafeInteger(journal.observed_pending_nonce)
      || journal.observed_pending_nonce < journal.observed_finalized_nonce
      || !Array.isArray(journal.allocations)) {
    throw new Error("wallet nonce allocator journal counters are invalid");
  }
  const nonces = new Set();
  for (const allocation of journal.allocations) {
    if (typeof allocation.action_id !== "string" || allocation.action_id.length < 1
        || !Number.isSafeInteger(allocation.nonce) || allocation.nonce < 0
        || !["reserved", "signed", "broadcast", "fenced"].includes(allocation.state)
        || (allocation.transaction_hash !== null && !ethers.isHexString(allocation.transaction_hash, 32))
        || nonces.has(allocation.nonce)) {
      throw new Error("wallet nonce allocator allocation is invalid");
    }
    nonces.add(allocation.nonce);
  }
  const floor = journal.allocations.reduce((highest, item) => Math.max(highest, item.nonce + 1), 0);
  if (journal.next_nonce < floor) throw new Error("wallet nonce allocator journal regressed");
  return journal;
}

function readJournal(path, expectedBinding) {
  if (!existsSync(path)) return {
    schema_version: "p42-wallet-nonce-allocator/v1",
    binding: expectedBinding,
    next_nonce: 0,
    observed_finalized_nonce: 0,
    observed_pending_nonce: 0,
    allocations: [],
  };
  return validateJournal(readStrictJsonFileSync(path, {
    ...LIMITS, privateFile: true, trustedRoot: dirname(path),
  }), expectedBinding);
}

async function nonceObservation(providers, signer) {
  if (!Array.isArray(providers) || providers.length < 2 || new Set(providers).size !== providers.length) {
    throw new Error("wallet nonce allocator requires independent RPC providers");
  }
  const observations = await Promise.all(providers.map(async (provider) => {
    const [finalizedNonce, pendingNonce] = await Promise.all([
      provider.getTransactionCount(signer, "finalized"),
      provider.getTransactionCount(signer, "pending"),
    ]);
    return { finalizedNonce, pendingNonce };
  }));
  const finalizedNonce = Math.max(...observations.map((item) => item.finalizedNonce));
  const pendingNonce = Math.max(...observations.map((item) => item.pendingNonce));
  if (!Number.isSafeInteger(finalizedNonce) || finalizedNonce < 0
      || !Number.isSafeInteger(pendingNonce) || pendingNonce < finalizedNonce) {
    throw new Error("RPC returned invalid finalized or pending wallet nonce evidence");
  }
  return { finalizedNonce, pendingNonce };
}

function signedTransaction(record, expectedBinding) {
  if (!record || record.schema_version !== "p42-signed-transaction/v1" || !ethers.isHexString(record.raw_tx)) {
    throw new Error("wallet nonce allocator signed record is invalid");
  }
  const transaction = ethers.Transaction.from(record.raw_tx);
  if (!transaction.from || transaction.from.toLowerCase() !== expectedBinding.signer
      || Number(transaction.chainId) !== expectedBinding.chain_id
      || transaction.nonce !== Number(record.nonce)
      || ethers.keccak256(record.raw_tx).toLowerCase() !== String(record.hash).toLowerCase()) {
    throw new Error("wallet nonce allocator signed record identity mismatch");
  }
  return transaction;
}

export async function reserveWalletNonceLocked({
  rpcProviders, coordinationRoot, boundChainId, signer, actionId, existingSignedRecord = null,
}) {
  const expectedBinding = binding(boundChainId, signer);
  const path = walletNonceAllocatorPath({ coordinationRoot, boundChainId, signer });
  const journal = readJournal(path, expectedBinding);
  const observation = await nonceObservation(rpcProviders, expectedBinding.signer);
  journal.observed_finalized_nonce = Math.max(journal.observed_finalized_nonce, observation.finalizedNonce);
  journal.observed_pending_nonce = Math.max(journal.observed_pending_nonce, observation.pendingNonce);

  if (existingSignedRecord) {
    const transaction = signedTransaction(existingSignedRecord, expectedBinding);
    const conflict = journal.allocations.find(
      (item) => item.nonce === transaction.nonce && item.action_id !== actionId,
    );
    if (conflict) throw new Error(`wallet nonce ${transaction.nonce} belongs to another action`);
    let allocation = journal.allocations.find(
      (item) => item.action_id === actionId && item.nonce === transaction.nonce,
    );
    if (!allocation) {
      allocation = {
        action_id: actionId, nonce: transaction.nonce, state: "signed",
        transaction_hash: existingSignedRecord.hash.toLowerCase(),
      };
      journal.allocations.push(allocation);
    } else if (allocation.transaction_hash
        && allocation.transaction_hash !== existingSignedRecord.hash.toLowerCase()) {
      throw new Error("wallet nonce allocation is bound to a different signed transaction");
    }
    journal.next_nonce = Math.max(journal.next_nonce, transaction.nonce + 1);
    durableReplaceCanonical(path, validateJournal(journal, expectedBinding));
    return { path, nonce: transaction.nonce, recovered: true };
  }

  const prior = [...journal.allocations].reverse().find(
    (item) => item.action_id === actionId && item.state === "reserved",
  );
  if (prior && prior.nonce >= observation.finalizedNonce && prior.nonce >= observation.pendingNonce) {
    durableReplaceCanonical(path, validateJournal(journal, expectedBinding));
    return { path, nonce: prior.nonce, recovered: true };
  }
  if (prior) prior.state = "fenced";
  const nonce = Math.max(journal.next_nonce, observation.finalizedNonce, observation.pendingNonce);
  journal.allocations.push({ action_id: actionId, nonce, state: "reserved", transaction_hash: null });
  journal.next_nonce = nonce + 1;
  durableReplaceCanonical(path, validateJournal(journal, expectedBinding));
  return { path, nonce, recovered: false };
}

export function recordWalletNonceSignedLocked({
  coordinationRoot, boundChainId, signer, actionId, signedRecord, state = "signed",
}) {
  const expectedBinding = binding(boundChainId, signer);
  const transaction = signedTransaction(signedRecord, expectedBinding);
  const path = walletNonceAllocatorPath({ coordinationRoot, boundChainId, signer });
  const journal = readJournal(path, expectedBinding);
  const allocation = journal.allocations.find(
    (item) => item.action_id === actionId && item.nonce === transaction.nonce,
  );
  if (!allocation || allocation.state === "fenced") {
    throw new Error("signed transaction lacks an active durable wallet nonce reservation");
  }
  if (allocation.transaction_hash && allocation.transaction_hash !== signedRecord.hash.toLowerCase()) {
    throw new Error("wallet nonce reservation already names another transaction");
  }
  allocation.transaction_hash = signedRecord.hash.toLowerCase();
  allocation.state = state === "broadcast" || allocation.state === "broadcast" ? "broadcast" : "signed";
  durableReplaceCanonical(path, validateJournal(journal, expectedBinding));
}

export async function walletNonceBroadcastDecisionLocked({
  rpcProvider, rpcProviders, coordinationRoot, boundChainId, signer, actionId, signedRecord,
}) {
  recordWalletNonceSignedLocked({ coordinationRoot, boundChainId, signer, actionId, signedRecord });
  const expectedBinding = binding(boundChainId, signer);
  const transaction = signedTransaction(signedRecord, expectedBinding);
  const known = await rpcProvider.getTransaction(signedRecord.hash);
  if (known) {
    if (!sameKnownTransaction(known, signedRecord, transaction, expectedBinding)) {
      throw new Error("RPC transaction identity disagrees with wallet nonce allocation");
    }
    return { broadcast: false, known: true, nonce: transaction.nonce };
  }
  const observation = await nonceObservation(rpcProviders, expectedBinding.signer);
  if (observation.finalizedNonce > transaction.nonce || observation.pendingNonce > transaction.nonce) {
    const path = walletNonceAllocatorPath({ coordinationRoot, boundChainId, signer });
    const journal = readJournal(path, expectedBinding);
    const allocation = journal.allocations.find((item) => item.action_id === actionId);
    allocation.state = "fenced";
    durableReplaceCanonical(path, validateJournal(journal, expectedBinding));
    return { broadcast: false, known: false, nonce: transaction.nonce, reason: "wallet nonce advanced" };
  }
  return { broadcast: true, known: false, nonce: transaction.nonce };
}

function sameKnownTransaction(known, record, transaction, expectedBinding) {
  return String(known.hash).toLowerCase() === record.hash.toLowerCase()
    && Number(known.nonce) === transaction.nonce
    && String(known.from).toLowerCase() === expectedBinding.signer;
}

export async function withWalletActionLock(args, operation) {
  const lockPath = walletActionLockPath(args);
  const owner = acquireEnvelopeLock(lockPath, { timeoutMs: args.timeoutMs ?? 30_000 });
  try { return await operation(); } finally { releaseEnvelopeLock(lockPath, owner); }
}
