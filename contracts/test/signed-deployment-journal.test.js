import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmdirSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { network } from "hardhat";
import {
  buildDeploymentNoncePlan,
  persistSignedDeployment,
  deploymentLockOwnerIdentity,
  readSignedDeploymentJournal,
  reconcileSignedDeployment,
  reserveDeploymentNoncePlan,
  signedDeploymentJournalPath,
} from "../scripts/signed-deployment-journal.js";

const { ethers } = await network.create();

async function fixture(run) {
  const directory = await mkdtemp(join(tmpdir(), "p42-signed-deploy-"));
  try { await run(directory); } finally { await rm(directory, { recursive: true, force: true }); }
}

async function signedFixture(directory, count = 2) {
  const wallet = ethers.Wallet.createRandom();
  const path = signedDeploymentJournalPath(join(directory, "manifest.json"));
  const plan = buildDeploymentNoncePlan(ethers, {
    identityDigest: `sha256:${"a".repeat(64)}`,
    network: "baseSepolia", chainId: 84532, deployer: wallet.address, startNonce: 17,
    rpcEvidence: {
      primaryOperatorId: "operator-a", secondaryOperatorId: "operator-b",
      primaryOrigin: "https://rpc-a.example", secondaryOrigin: "https://rpc-b.example",
      primaryHost: "rpc-a.example", secondaryHost: "rpc-b.example",
      primaryEndpointDigest: `sha256:${"1".repeat(64)}`, secondaryEndpointDigest: `sha256:${"2".repeat(64)}`,
    },
    steps: Array.from({ length: count }, (_, index) => ({ name: `step-${index}`, constructorArgsHash: `0x${String(index + 1).repeat(64)}`, expectedInitCode: "0x6000" })),
  });
  reserveDeploymentNoncePlan(path, plan);
  const raw = await wallet.signTransaction({ chainId: 84532, nonce: 17, gasLimit: 100000, gasPrice: 1, data: "0x6000" });
  persistSignedDeployment(path, plan.planDigest, 0, ethers, raw);
  return { wallet, path, plan, raw };
}

function providerFor({ transaction = null, receipt = null, block = null, latest = 17, pending = 17, onBroadcast = undefined } = {}) {
  return {
    async getTransactionReceipt() { return receipt; },
    async getTransaction() { return transaction; },
    async getBlock() { return block; },
    async getBlockNumber() { return block?.number ?? 999; },
    async getTransactionCount(_address, tag) { return tag === "latest" ? latest : pending; },
    async broadcastTransaction(raw) {
      if (onBroadcast) return onBroadcast(raw);
      return { hash: ethers.keccak256(raw) };
    },
  };
}

function writeCrashLock(path, owner) {
  mkdirSync(`${path}.lock`, { mode: 0o700 });
  writeFileSync(`${path}.lock/owner.json`, `${JSON.stringify({ ...owner, createdAt: new Date(0).toISOString(), token: "stale-token" })}\n`, { mode: 0o600 });
}

describe("signed deployment journal fail-closed recovery", () => {
  it("durably reserves the exact nonce range and deterministic identities before signing", async () => {
    await fixture(async (directory) => {
      const { path, plan } = await signedFixture(directory, 3);
      const journal = readSignedDeploymentJournal(path);
      assert.equal(journal.startNonce, 17);
      assert.equal(journal.endNonceExclusive, 20);
      assert.deepEqual(journal.steps.map((step) => step.nonce), [17, 18, 19]);
      assert.equal(journal.steps[1].address, ethers.getCreateAddress({ from: journal.deployer, nonce: 18 }));
      const drift = structuredClone(plan);
      drift.startNonce = 18;
      assert.throws(() => reserveDeploymentNoncePlan(path, drift), /does not match|range/);
    });
  });

  it("has fsynced signed bytes and expected hash before the first broadcast call", async () => {
    await fixture(async (directory) => {
      const { path, plan, raw } = await signedFixture(directory);
      let observed;
      const provider = providerFor({ onBroadcast(bytes) {
        observed = JSON.parse(readFileSync(path, "utf8")).steps[0];
        assert.equal(bytes, raw);
        return { hash: ethers.keccak256(bytes) };
      } });
      const result = await reconcileSignedDeployment({ ethers, provider, journalPath: path, planDigest: plan.planDigest, index: 0 });
      assert.equal(observed.state, "signed");
      assert.equal(observed.rawTransaction, raw);
      assert.equal(observed.expectedHash, ethers.keccak256(raw));
      assert.equal(result.state, "broadcast");
    });
  });

  it("recovers crashes before and after broadcast by using identical bytes only", async () => {
    await fixture(async (directory) => {
      const { wallet, path, plan, raw } = await signedFixture(directory);
      const hash = ethers.keccak256(raw);
      await assert.rejects(
        () => reconcileSignedDeployment({ ethers, provider: providerFor({ onBroadcast() { throw new Error("crash after provider acceptance"); } }), journalPath: path, planDigest: plan.planDigest, index: 0 }),
        /crash after provider acceptance/,
      );
      assert.equal(readSignedDeploymentJournal(path).steps[0].state, "signed");
      const pendingTx = { hash, nonce: 17, from: wallet.address, to: null };
      const pending = await reconcileSignedDeployment({ ethers, provider: providerFor({ transaction: pendingTx, pending: 18 }), journalPath: path, planDigest: plan.planDigest, index: 0 });
      assert.equal(pending.state, "pending");
      const address = readSignedDeploymentJournal(path).steps[0].address;
      const receipt = { status: 1, blockNumber: 99, blockHash: `0x${"b".repeat(64)}`, transactionHash: hash, contractAddress: address };
      const block = { number: 99, hash: receipt.blockHash };
      const minedProvider = providerFor({ receipt, transaction: pendingTx, block, latest: 18, pending: 18 });
      const mined = await reconcileSignedDeployment({ ethers, provider: minedProvider, secondaryProvider: minedProvider, journalPath: path, planDigest: plan.planDigest, index: 0 });
      assert.equal(mined.state, "mined");
      assert.equal(readSignedDeploymentJournal(path).steps[0].blockNumber, 99);
    });
  });

  it("fails closed on nonce consumption, pending identity drift, tampering, and state regression", async () => {
    await fixture(async (directory) => {
      const { wallet, path, plan, raw } = await signedFixture(directory);
      await assert.rejects(
        () => reconcileSignedDeployment({ ethers, provider: providerFor({ latest: 18, pending: 18 }), journalPath: path, planDigest: plan.planDigest, index: 0 }),
        /nonce drift.*refusing replacement/,
      );
      await assert.rejects(
        () => reconcileSignedDeployment({ ethers, provider: providerFor({ transaction: { hash: ethers.keccak256(raw), nonce: 18, from: wallet.address } }), journalPath: path, planDigest: plan.planDigest, index: 0 }),
        /identity drift/,
      );
      const record = JSON.parse(readFileSync(path, "utf8"));
      record.steps[0].nonce = 999;
      writeFileSync(path, `${JSON.stringify(record)}\n`);
      chmodSync(path, 0o600);
      assert.throws(() => readSignedDeploymentJournal(path), /identity or nonce drift/);
    });
  });

  it("rejects raw signed transaction substitution even when adjacent fields are edited", async () => {
    await fixture(async (directory) => {
      const { path } = await signedFixture(directory);
      const attacker = ethers.Wallet.createRandom();
      const replacement = await attacker.signTransaction({ chainId: 84532, nonce: 17, gasLimit: 100000, gasPrice: 1, data: "0x6000" });
      const record = JSON.parse(readFileSync(path, "utf8"));
      record.steps[0].rawTransaction = replacement;
      record.steps[0].expectedHash = ethers.keccak256(replacement);
      writeFileSync(path, `${JSON.stringify(record)}\n`, { mode: 0o600 });
      assert.throws(() => readSignedDeploymentJournal(path), /payload identity drift|payload digest mismatch/);
    });
  });

  it("binds exact initcode in the immutable plan and rejects a differently populated deployment", async () => {
    await fixture(async (directory) => {
      const { wallet, path, plan } = await signedFixture(directory);
      const wrongRaw = await wallet.signTransaction({ chainId: 84532, nonce: 17, gasLimit: 100000, gasPrice: 1, data: "0x6001" });
      assert.throws(() => persistSignedDeployment(path, plan.planDigest, 0, ethers, wrongRaw), /initcode differs from immutable/);
      const record = JSON.parse(readFileSync(path, "utf8"));
      record.steps[0].expectedInitCode = "0x6001";
      writeFileSync(path, `${JSON.stringify(record)}\n`, { mode: 0o600 });
      assert.throws(() => readSignedDeploymentJournal(path), /plan initcode hash mismatch/);
    });
  });

  it("rejects common RPC operators and endpoint aliases in the immutable plan", async () => {
    const wallet = ethers.Wallet.createRandom();
    const base = {
      identityDigest: `sha256:${"a".repeat(64)}`, network: "baseSepolia", chainId: 84532,
      deployer: wallet.address, startNonce: 1,
      steps: [{ name: "one", constructorArgsHash: `0x${"1".repeat(64)}`, expectedInitCode: "0x6000" }],
    };
    const evidence = {
      primaryOperatorId: "same", secondaryOperatorId: "same",
      primaryOrigin: "https://a.example", secondaryOrigin: "https://b.example",
      primaryHost: "a.example", secondaryHost: "b.example",
      primaryEndpointDigest: `sha256:${"1".repeat(64)}`, secondaryEndpointDigest: `sha256:${"2".repeat(64)}`,
    };
    assert.throws(() => buildDeploymentNoncePlan(ethers, { ...base, rpcEvidence: evidence }), /not independent/);
    assert.throws(() => buildDeploymentNoncePlan(ethers, { ...base, rpcEvidence: { ...evidence, secondaryOperatorId: "other", secondaryOrigin: "https://a.example", secondaryHost: "a.example" } }), /not independent/);
  });

  it("rejects forged receipts and refuses mined state without independent RPC evidence", async () => {
    await fixture(async (directory) => {
      const { wallet, path, plan, raw } = await signedFixture(directory);
      const hash = ethers.keccak256(raw);
      const step = readSignedDeploymentJournal(path).steps[0];
      const tx = { hash, nonce: 17, from: wallet.address, to: null };
      const forged = { status: 1, blockNumber: 3, blockHash: `0x${"c".repeat(64)}`, transactionHash: hash, contractAddress: ethers.Wallet.createRandom().address };
      const provider = providerFor({ receipt: forged, transaction: tx, block: { number: 3, hash: forged.blockHash } });
      await assert.rejects(() => reconcileSignedDeployment({ provider, secondaryProvider: provider, journalPath: path, planDigest: plan.planDigest, index: 0 }), /receipt identity mismatch/);
      const valid = { ...forged, contractAddress: step.address };
      const primary = providerFor({ receipt: valid, transaction: tx, block: { number: 3, hash: valid.blockHash } });
      await assert.rejects(() => reconcileSignedDeployment({ provider: primary, journalPath: path, planDigest: plan.planDigest, index: 0 }), /secondary independently configured/);
    });
  });

  it("excludes concurrent reconciliation runners across the broadcast boundary", async () => {
    await fixture(async (directory) => {
      const { path, plan } = await signedFixture(directory);
      let release;
      const gate = new Promise((resolve) => { release = resolve; });
      const provider = providerFor({ async onBroadcast(raw) { await gate; return { hash: ethers.keccak256(raw) }; } });
      const first = reconcileSignedDeployment({ provider, journalPath: path, planDigest: plan.planDigest, index: 0 });
      await new Promise((resolve) => setTimeout(resolve, 20));
      await assert.rejects(() => reconcileSignedDeployment({ provider, journalPath: path, planDigest: plan.planDigest, index: 0 }), /another signed deployment runner/);
      release();
      await first;
      const successor = await reconcileSignedDeployment({ provider, journalPath: path, planDigest: plan.planDigest, index: 0 });
      assert.equal(successor.state, "broadcast");
    });
  });

  it("reclaims a provably dead crash lock and a PID-reuse lock", async () => {
    await fixture(async (directory) => {
      for (const owner of [
        { ...deploymentLockOwnerIdentity(), pid: 999999999, processStartId: "dead-process" },
        { ...deploymentLockOwnerIdentity(), processStartId: "reused-process-start" },
      ]) {
        const { path, plan } = await signedFixture(directory, 1);
        writeCrashLock(path, owner);
        const result = await reconcileSignedDeployment({ provider: providerFor(), journalPath: path, planDigest: plan.planDigest, index: 0 });
        assert.equal(result.state, "broadcast");
        await rm(path, { force: true });
      }
    });
  });

  it("allows only one simultaneous stale-lock reclaimer and never removes its successor", async () => {
    await fixture(async (directory) => {
      const { path, plan } = await signedFixture(directory);
      writeCrashLock(path, { ...deploymentLockOwnerIdentity(), pid: 999999999, processStartId: "dead-process" });
      let release;
      const gate = new Promise((resolve) => { release = resolve; });
      const provider = providerFor({ async onBroadcast(raw) { await gate; return { hash: ethers.keccak256(raw) }; } });
      const first = reconcileSignedDeployment({ provider, journalPath: path, planDigest: plan.planDigest, index: 0 });
      await new Promise((resolve) => setTimeout(resolve, 20));
      const second = reconcileSignedDeployment({ provider, journalPath: path, planDigest: plan.planDigest, index: 0 });
      await assert.rejects(() => second, /another signed deployment runner/);
      release();
      await first;
      const successor = await reconcileSignedDeployment({ provider: providerFor(), journalPath: path, planDigest: plan.planDigest, index: 0 });
      assert.equal(successor.state, "broadcast");
    });
  });

  it("never publishes a live lock when the runner crashes after candidate durability", async () => {
    await fixture(async (directory) => {
      const { path, plan } = await signedFixture(directory);
      let candidate;
      await assert.rejects(
        () => reconcileSignedDeployment({
          provider: providerFor(), journalPath: path, planDigest: plan.planDigest, index: 0,
          lockHooks: { async afterCandidateDurable(value) { candidate = value; throw new Error("simulated crash before lock publication"); } },
        }),
        /simulated crash/,
      );
      assert.equal(existsSync(`${path}.lock`), false);
      assert.equal(existsSync(`${candidate}/owner.json`), true);
      await rm(candidate, { recursive: true, force: true });
      const recovered = await reconcileSignedDeployment({ provider: providerFor(), journalPath: path, planDigest: plan.planDigest, index: 0 });
      assert.equal(recovered.state, "broadcast");
    });
  });

  it("fails closed on an incomplete legacy live lock until explicit operator recovery", async () => {
    await fixture(async (directory) => {
      const { path, plan } = await signedFixture(directory);
      mkdirSync(`${path}.lock`, { mode: 0o700 });
      await assert.rejects(
        () => reconcileSignedDeployment({ provider: providerFor(), journalPath: path, planDigest: plan.planDigest, index: 0 }),
        /incomplete live deployment lock requires explicit operator recovery/,
      );
      assert.equal(existsSync(`${path}.lock`), true);
      rmdirSync(`${path}.lock`);
      const recovered = await reconcileSignedDeployment({ provider: providerFor(), journalPath: path, planDigest: plan.planDigest, index: 0 });
      assert.equal(recovered.state, "broadcast");
    });
  });

  it("rechecks both receipts and canonical blocks after confirmation heads", async () => {
    await fixture(async (directory) => {
      const { wallet, path, plan, raw } = await signedFixture(directory);
      const step = readSignedDeploymentJournal(path).steps[0];
      const hash = ethers.keccak256(raw);
      const receipt = { status: 1, blockNumber: 5, blockHash: `0x${"d".repeat(64)}`, transactionHash: hash, contractAddress: step.address };
      let reads = 0;
      const provider = providerFor({ receipt, transaction: { hash, nonce: 17, from: wallet.address, to: null }, block: { number: 5, hash: receipt.blockHash } });
      provider.getTransactionReceipt = async () => (++reads > 1 ? { ...receipt, blockHash: `0x${"e".repeat(64)}` } : receipt);
      await assert.rejects(
        () => reconcileSignedDeployment({ provider, secondaryProvider: providerFor({ receipt, transaction: { hash, nonce: 17, from: wallet.address, to: null }, block: { number: 5, hash: receipt.blockHash } }), journalPath: path, planDigest: plan.planDigest, index: 0 }),
        /final primary receipt block is not canonical|evidence changed/,
      );
    });
  });

  it("rejects a receipt whose block hash is orphaned at its canonical block number", async () => {
    await fixture(async (directory) => {
      const { wallet, path, plan, raw } = await signedFixture(directory);
      const step = readSignedDeploymentJournal(path).steps[0];
      const hash = ethers.keccak256(raw);
      const receipt = { status: 1, blockNumber: 5, blockHash: `0x${"a".repeat(64)}`, transactionHash: hash, contractAddress: step.address };
      const tx = { hash, nonce: 17, from: wallet.address, to: null };
      const provider = providerFor({ receipt, transaction: tx, block: { number: 5, hash: receipt.blockHash } });
      provider.getBlock = async (selector) => typeof selector === "number" ? { number: 5, hash: `0x${"b".repeat(64)}` } : { number: 5, hash: receipt.blockHash };
      const secondary = providerFor({ receipt, transaction: tx, block: { number: 5, hash: receipt.blockHash } });
      await assert.rejects(() => reconcileSignedDeployment({ provider, secondaryProvider: secondary, journalPath: path, planDigest: plan.planDigest, index: 0 }), /final primary receipt block is not canonical/);
    });
  });

  it("rejects a final receipt status flip after confirmation heads", async () => {
    await fixture(async (directory) => {
      const { wallet, path, plan, raw } = await signedFixture(directory);
      const step = readSignedDeploymentJournal(path).steps[0];
      const hash = ethers.keccak256(raw);
      const receipt = { status: 1, blockNumber: 5, blockHash: `0x${"c".repeat(64)}`, transactionHash: hash, contractAddress: step.address };
      const tx = { hash, nonce: 17, from: wallet.address, to: null };
      let reads = 0;
      const primary = providerFor({ receipt, transaction: tx, block: { number: 5, hash: receipt.blockHash } });
      primary.getTransactionReceipt = async () => (++reads > 1 ? { ...receipt, status: 0 } : receipt);
      const secondary = providerFor({ receipt, transaction: tx, block: { number: 5, hash: receipt.blockHash } });
      await assert.rejects(() => reconcileSignedDeployment({ provider: primary, secondaryProvider: secondary, journalPath: path, planDigest: plan.planDigest, index: 0 }), /receipt status changed/);
    });
  });

  it("rejects symlink substitution at the journal read boundary", async () => {
    await fixture(async (directory) => {
      const { path } = await signedFixture(directory);
      const target = join(directory, "target.json");
      writeFileSync(target, readFileSync(path), { mode: 0o600 });
      unlinkSync(path);
      symlinkSync(target, path);
      assert.throws(() => readSignedDeploymentJournal(path), /symlink|ELOOP|inode changed/);
    });
  });

  it("detects an inode swap while reconciliation is awaiting RPC evidence", async () => {
    await fixture(async (directory) => {
      const { path, plan } = await signedFixture(directory);
      const replacement = join(directory, "replacement.json");
      const provider = providerFor();
      provider.getTransactionReceipt = async () => {
        writeFileSync(replacement, readFileSync(path), { mode: 0o600 });
        renameSync(replacement, path);
        return null;
      };
      await assert.rejects(
        () => reconcileSignedDeployment({ provider, journalPath: path, planDigest: plan.planDigest, index: 0 }),
        /pathname changed during reconciliation/,
      );
    });
  });
});
