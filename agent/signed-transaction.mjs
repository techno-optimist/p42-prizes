import { lstatSync, realpathSync } from "node:fs";
import { basename, dirname, relative, resolve } from "node:path";
import { ethers } from "ethers";

function sameAddress(left, right) {
  return ethers.getAddress(left) === ethers.getAddress(right);
}

function sameHex(left, right) {
  return String(left).toLowerCase() === String(right).toLowerCase();
}

export function assertApprovedJournalPath(path, approvedRoot, expectedPath = undefined) {
  const root = realpathSync(resolve(approvedRoot));
  const candidate = resolve(path);
  const parent = realpathSync(dirname(candidate));
  const canonicalCandidate = resolve(parent, basename(candidate));
  const rel = relative(root, canonicalCandidate);
  if (parent !== root || rel.startsWith("..") || rel === "" || rel.includes("/")) {
    throw new Error("signed transaction journal path is outside the approved journal root");
  }
  if (expectedPath !== undefined) {
    const expected = resolve(realpathSync(dirname(resolve(expectedPath))), basename(resolve(expectedPath)));
    if (canonicalCandidate !== expected) {
    throw new Error("signed transaction journal path does not match the derived journal path");
    }
  }
  const stat = lstatSync(candidate);
  if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(candidate) !== canonicalCandidate) {
    throw new Error("signed transaction journal must be a regular non-symlink file");
  }
  return canonicalCandidate;
}

export function assertSignedTransactionRecord(record, expected) {
  if (record?.schema_version !== "p42-signed-transaction/v1") {
    throw new Error("signed transaction journal has an unsupported schema");
  }
  if (!ethers.isHexString(record.raw_tx)) throw new Error("signed transaction journal raw_tx is invalid");
  const rawHash = ethers.keccak256(record.raw_tx);
  if (!sameHex(rawHash, record.hash)) throw new Error("signed transaction journal raw transaction hash mismatch");
  const persistedHashes = [expected.hash, ...(expected.hashes ?? [])].filter((hash) => hash !== undefined && hash !== null);
  for (const hash of persistedHashes) {
    if (!sameHex(rawHash, hash)) {
      throw new Error("signed transaction journal hash does not match persisted transaction hash");
    }
  }

  const transaction = ethers.Transaction.from(record.raw_tx);
  if (!transaction.from || !sameAddress(transaction.from, expected.signer) || !sameAddress(record.signer, expected.signer)) {
    throw new Error("signed transaction journal signer mismatch");
  }
  if (Number(transaction.chainId) !== Number(expected.chainId) || Number(record.chain_id) !== Number(expected.chainId)) {
    throw new Error("signed transaction journal chain mismatch");
  }
  if (!transaction.to || !sameAddress(transaction.to, expected.to) || !sameAddress(record.to, expected.to)) {
    throw new Error("signed transaction journal destination mismatch");
  }
  if (!sameHex(transaction.data, expected.data)) throw new Error("signed transaction journal calldata mismatch");
  const dataHash = ethers.keccak256(transaction.data);
  if (!sameHex(record.data_hash, dataHash)) throw new Error("signed transaction journal declared calldata hash mismatch");
  if (transaction.value !== BigInt(expected.value) || BigInt(record.value) !== transaction.value) {
    throw new Error("signed transaction journal value mismatch");
  }
  if (transaction.nonce !== Number(record.nonce)) throw new Error("signed transaction journal nonce mismatch");
  if (expected.nonce !== undefined && transaction.nonce !== Number(expected.nonce)) {
    throw new Error("signed transaction journal nonce does not match persisted nonce");
  }
  if (expected.label !== undefined && record.label !== expected.label) {
    throw new Error("signed transaction journal label binding mismatch");
  }
  return { record, transaction, hash: rawHash };
}
