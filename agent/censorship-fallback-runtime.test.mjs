import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";

import { ethers } from "ethers";

import { buildForcedChallengePlan, applyL1ToL2Alias } from "./censorship-fallback.mjs";
import { assertDistinctHttpsRpcUrls } from "./censorship-fallback-run.mjs";
import {
  advanceFallbackRun,
  createEthersFallbackAdapter,
  fallbackWalletNonceActionId,
  validateFallbackAuthorization,
  validateFallbackPlan,
  validateFallbackRunState,
  verifyCompletedFallbackRun,
} from "./censorship-fallback-runtime.mjs";
import { buildSignedTransactionRecord, canonicalJson, sha256Canonical } from "./lib.mjs";

const roots = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function authorizationFor({ plan, operator, approver, overrides = {} }) {
  const payload = {
    schema: "p42-censorship-fallback-authorization/v1",
    planHash: sha256Canonical(plan),
    l1ChainId: 1,
    l2StartBlock: 0,
    operator,
    expiresAt: "3000000",
    maxBondWei: "100",
    maxPortalGasLimit: "2000000",
    maxL1GasLimit: "300000",
    maxFeePerGas: "3",
    maxPriorityFeePerGas: "2",
    maxRpcHeadLagBlocks: 4,
    maxL2ScanBlocks: 10000,
    maxL2Logs: 100,
    maxTotalL1FeeWei: "1000000",
    ...overrides,
  };
  const artifactHash = sha256Canonical(payload);
  return {
    ...payload,
    artifactHash,
    signature: {
      scheme: "eip191",
      signer: approver.address,
      signature: approver.signingKey.sign(ethers.hashMessage(artifactHash)).serialized,
    },
  };
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "p42-fallback-runtime-"));
  chmodSync(root, 0o700);
  roots.push(root);
  const statePath = join(root, "run.json");
  const signer = ethers.Wallet.createRandom();
  const controller = ethers.Wallet.createRandom().address;
  const wallet = ethers.Wallet.createRandom().address;
  const manager = ethers.Wallet.createRandom().address;
  const portal = ethers.Wallet.createRandom().address;
  const challenge = new ethers.Interface([
    "function challenge(uint256 submissionId,bytes32 revealInstanceHash,bytes32 reasonHash)",
  ]).encodeFunctionData("challenge", [9, ethers.id("reveal"), ethers.id("reason")]);
  const plan = buildForcedChallengePlan({
    l1Controller: controller,
    l1ControllerCodeHash: ethers.id("controller-code"),
    forcedInclusionOwner: applyL1ToL2Alias(controller),
    portal,
    wallet,
    challengeManager: manager,
    controllerBindings: {
      portal,
      l2Wallet: wallet,
      challengeManager: manager,
      challengeSelector: ethers.dataSlice(challenge, 0, 4),
    },
    challengeCalldata: challenge,
    bondWei: 10n,
    chainId: 8453,
    policyExpiresAt: 2_000_000,
    scopeHash: ethers.id("scope"),
    portalGasLimit: 1_500_000,
    challengeDeadline: 1_900_000,
    currentTimestamp: 1_000_000,
  });
  const approver = ethers.Wallet.createRandom();
  const authorization = authorizationFor({ plan, operator: signer.address, approver });
  return { root, statePath, signer, approver, authorization, plan };
}

function fakeAdapter(signer, { stopDeadlineAfterPolicy = false, policyUnavailableAfterFirst = false } = {}) {
  const signed = [];
  const reconciliations = { policy: 0, challenge: 0 };
  let policyObservations = 0;
  const executionPolicy = {
    l1GasLimit: "200000", maxFeePerGas: "2", maxPriorityFeePerGas: "1", maxRpcHeadLagBlocks: 2,
    maxL2ScanBlocks: 1000, maxL2Logs: 10,
  };
  const nonceProvider = {
    async getTransactionCount() { return 0; },
    async getTransaction() { return null; },
  };
  const nonceProviderSecondary = {
    async getTransactionCount() { return 0; },
    async getTransaction() { return null; },
  };
  return {
    executionPolicy,
    executionPolicyHash: sha256Canonical(executionPolicy),
    l1ChainId: 1,
    l2StartBlock: 0,
    l2StartBlock: 0,
    operator: signer.address,
    nonceRpcProvider: nonceProvider,
    nonceRpcProviders: [nonceProvider, nonceProviderSecondary],
    signed,
    async assertBindings() {},
    async assertAuthorizationDeadline() {},
    async assertDeadline(_plan, action) {
      if (stopDeadlineAfterPolicy && action === "challenge") throw new Error("deadline slack exhausted");
    },
    async prepare(_action, transaction) { return transaction; },
    async sign(action, transaction, plan, nonce) {
      signed.push(action);
      return buildSignedTransactionRecord({
        wallet: signer,
        request: {
          to: transaction.to,
          data: transaction.calldata,
          value: BigInt(transaction.valueWei),
          chainId: 1,
          nonce,
          gasLimit: 200_000,
          maxFeePerGas: 2,
          maxPriorityFeePerGas: 1,
          type: 2,
        },
        chainId: 1,
        label: `censorship-fallback:${plan.calldataHash}:${action}`,
      });
    },
    async broadcastL1() {},
    async reconcileL1(action, record) {
      reconciliations[action] += 1;
      if (reconciliations[action] === 1) return { status: "pending" };
      return {
        status: "final",
        anchor: {
          blockNumber: action === "policy" ? 100 : 110,
          blockHash: ethers.id(`${action}-l1-block`),
          transactionHash: record.hash,
        },
      };
    },
    async observePolicy(plan) {
      policyObservations += 1;
      if (policyUnavailableAfterFirst && policyObservations > 1) return { status: "pending" };
      return {
        status: "confirmed",
        anchor: { blockNumber: 200, blockHash: ethers.id("policy-l2-block"), transactionHash: plan.calldataHash },
      };
    },
    async observeChallenge(plan) {
      const outer = new ethers.Interface([
        "function depositChallenge(bytes challengeCalldata,uint256 bondWei,uint64 l2GasLimit)",
      ]).decodeFunctionData("depositChallenge", plan.deposits[1].calldata);
      const decoded = new ethers.Interface([
        "function challenge(uint256 submissionId,bytes32 revealInstanceHash,bytes32 reasonHash)",
      ]).decodeFunctionData("challenge", outer.challengeCalldata);
      const challengedAt = 1_000n;
      const disputeEndsAt = 2_000n;
      const challengeInstanceHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "uint256", "uint256", "bytes32", "address", "bytes32", "uint64", "uint64"],
        [
          plan.challengeManager, BigInt(plan.l2ChainId), decoded.submissionId,
          decoded.revealInstanceHash, plan.wallet, decoded.reasonHash, challengedAt, disputeEndsAt,
        ],
      ));
      return {
        status: "confirmed",
        anchor: {
          blockNumber: 210,
          blockHash: ethers.id("challenge-l2-block"),
          transactionHash: plan.scopeHash,
          challengedAt: challengedAt.toString(),
          disputeEndsAt: disputeEndsAt.toString(),
          challengeInstanceHash,
          revealInstanceHash: decoded.revealInstanceHash,
        },
      };
    },
    async revalidateComplete() {},
  };
}

async function advance(f, adapter) {
  return advanceFallbackRun({
    statePath: f.statePath,
    stateRoot: f.root,
    plan: f.plan,
    l1ChainId: 1,
    l2StartBlock: 0,
    l2StartBlock: 0,
    operator: f.signer.address,
    adapter,
    executionPolicy: adapter.executionPolicy,
    authorization: f.authorization,
    authorizationApprover: f.approver.address,
    coordinationRoot: f.root,
  });
}

it("rejects adapters bound to another chain, operator, or observation range", async () => {
  const f = fixture();
  for (const override of [
    { l1ChainId: 2 },
    { l2StartBlock: 1 },
    { operator: ethers.Wallet.createRandom().address },
  ]) {
    const adapter = Object.assign(fakeAdapter(f.signer), override);
    await assert.rejects(advance(f, adapter), /adapter identity does not match journal bindings/);
  }
  await assert.rejects(
    advanceFallbackRun({
      statePath: f.statePath,
      stateRoot: f.root,
      plan: f.plan,
      l1ChainId: 2n ** 60n,
      l2StartBlock: 0,
      operator: f.signer.address,
      adapter: fakeAdapter(f.signer),
      executionPolicy: fakeAdapter(f.signer).executionPolicy,
      coordinationRoot: f.root,
    }),
    /positive safe L1 chain id/,
  );
  assert.throws(
    () => validateFallbackPlan({ ...f.plan, l2ChainId: (2n ** 60n).toString() }),
    /economic or deadline binding is invalid/,
  );
});

it("recomputes deadline budgets and requires independent capped authorization", () => {
  const f = fixture();
  for (const mutation of [
    { requiredRemainingSeconds: "2", singleDepositRequiredSeconds: "1" },
    { sequencingWindowL1Blocks: "1" },
    { l1BlockSeconds: "1" },
  ]) {
    assert.throws(
      () => validateFallbackPlan({ ...f.plan, ...mutation }),
      /economic or deadline binding is invalid/,
    );
  }
  const policy = fakeAdapter(f.signer).executionPolicy;
  assert.equal(validateFallbackAuthorization(f.authorization, {
    plan: f.plan,
    l1ChainId: 1,
    l2StartBlock: 0,
    operator: f.signer.address,
    expectedApprover: f.approver.address,
    executionPolicy: policy,
  }).artifactHash, f.authorization.artifactHash);
  assert.throws(() => validateFallbackAuthorization(
    authorizationFor({
      plan: f.plan,
      operator: f.signer.address,
      approver: f.approver,
      overrides: { maxBondWei: "5" },
    }),
    {
      plan: f.plan,
      l1ChainId: 1,
      l2StartBlock: 0,
      operator: f.signer.address,
      expectedApprover: f.approver.address,
      executionPolicy: policy,
    },
  ), /exceeds authorization caps/);
  assert.throws(() => validateFallbackAuthorization(f.authorization, {
    plan: f.plan,
    l1ChainId: 1,
    l2StartBlock: 0,
    operator: f.signer.address,
    expectedApprover: f.signer.address,
    executionPolicy: policy,
  }), /authorization identity is invalid/);
});

it("gives each journal phase a distinct wallet-wide nonce action identity", () => {
  const f = fixture();
  const common = {
    planHash: sha256Canonical(f.plan),
    executionPolicyHash: sha256Canonical(fakeAdapter(f.signer).executionPolicy),
    l1ChainId: 1,
    signer: f.signer.address,
  };
  const policy = fallbackWalletNonceActionId({ ...common, statePath: f.statePath, action: "policy" });
  assert.equal(policy, fallbackWalletNonceActionId({ ...common, statePath: f.statePath, action: "policy" }));
  assert.notEqual(policy, fallbackWalletNonceActionId({ ...common, statePath: f.statePath, action: "challenge" }));
  assert.notEqual(policy, fallbackWalletNonceActionId({
    ...common, statePath: join(f.root, "another.json"), action: "policy",
  }));
});

it("requires credential-free independent HTTPS RPC hosts", () => {
  assert.deepEqual(assertDistinctHttpsRpcUrls(
    "https://rpc-a.example/", "https://rpc-b.example", "test",
  ), ["https://rpc-a.example/", "https://rpc-b.example/"]);
  for (const pair of [
    ["http://rpc-a.example", "https://rpc-b.example"],
    ["https://rpc.example/a", "https://rpc-b.example"],
    ["https://user:pass@rpc-a.example", "https://rpc-b.example"],
    ["https://rpc-a.example?key=secret", "https://rpc-b.example"],
    ["https://rpc.example", "https://rpc.example:443"],
  ]) {
    assert.throws(() => assertDistinctHttpsRpcUrls(...pair, "test"), /RPC|HTTPS/);
  }
});

describe("crash-safe censorship fallback runtime", () => {
  it("allocates distinct wallet nonces across independent fallback journals", async () => {
    const f = fixture();
    const second = { ...f, statePath: join(f.root, "second-run.json") };
    const firstAdapter = fakeAdapter(f.signer);
    const secondAdapter = fakeAdapter(f.signer);
    await advance(f, firstAdapter);
    await advance(second, secondAdapter);
    const first = JSON.parse(readFileSync(f.statePath, "utf8"));
    const other = JSON.parse(readFileSync(second.statePath, "utf8"));
    assert.equal(ethers.Transaction.from(first.policy.signedTransaction.raw_tx).nonce, 0);
    assert.equal(ethers.Transaction.from(other.policy.signedTransaction.raw_tx).nonce, 1);
  });

  it("persists each signed transaction before broadcast and enforces ordered L2 confirmation", async () => {
    const f = fixture();
    const adapter = fakeAdapter(f.signer);

    assert.equal((await advance(f, adapter)).stage, "policy_broadcast");
    let disk = JSON.parse(readFileSync(f.statePath, "utf8"));
    assert.equal(disk.policy.signedTransaction.raw_tx.startsWith("0x"), true);
    assert.equal(disk.challenge.signedTransaction, null);

    assert.equal((await advance(f, adapter)).stage, "policy_l2_confirmed");
    assert.deepEqual(adapter.signed, ["policy"]);
    assert.equal((await advance(f, adapter)).stage, "challenge_broadcast");
    assert.deepEqual(adapter.signed, ["policy", "challenge"]);
    assert.equal((await advance(f, adapter)).stage, "challenge_l2_confirmed");

    disk = JSON.parse(readFileSync(f.statePath, "utf8"));
    validateFallbackRunState(disk, {
      plan: f.plan,
      l1ChainId: 1,
      l2StartBlock: 0,
      executionPolicyHash: adapter.executionPolicyHash,
      authorizationHash: f.authorization.artifactHash,
      operator: f.signer.address,
    });
    assert.equal(disk.policy.l1Anchor.transactionHash, disk.policy.signedTransaction.hash);
    assert.equal(disk.challenge.l1Anchor.transactionHash, disk.challenge.signedTransaction.hash);

    disk.policy.signedTransaction = await buildSignedTransactionRecord({
      wallet: f.signer,
      request: {
        to: f.plan.deposits[0].to,
        data: f.plan.deposits[0].calldata,
        value: BigInt(f.plan.deposits[0].valueWei),
        chainId: 1,
        nonce: Number(disk.policy.signedTransaction.nonce),
        gasLimit: BigInt(adapter.executionPolicy.l1GasLimit),
        maxFeePerGas: BigInt(adapter.executionPolicy.maxFeePerGas) + 1n,
        maxPriorityFeePerGas: BigInt(adapter.executionPolicy.maxPriorityFeePerGas),
        type: 2,
      },
      chainId: 1,
      label: `censorship-fallback:${f.plan.calldataHash}:policy`,
    });
    writeFileSync(f.statePath, `${canonicalJson(disk)}\n`, { mode: 0o600 });
    await assert.rejects(
      advance(f, adapter),
      /changes the authorized fee envelope/,
      "a completed-journal restart must not bypass raw signed fee validation",
    );
  });

  it("requires finalized dual-RPC storage and forced-deposit event provenance", async () => {
    const f = fixture();
    const code = "0x6000";
    f.plan.l1ControllerCodeHash = ethers.keccak256(code);
    const controllerInterface = new ethers.Interface([
      "function portal() view returns (address)",
      "function l2Wallet() view returns (address)",
      "function challengeManager() view returns (address)",
      "function challengeSelector() view returns (bytes4)",
      "function operator() view returns (address)",
    ]);
    const walletInterface = new ethers.Interface([
      "function forcedInclusionOwner() view returns (address)",
      "function allowed(address,bytes4) view returns (bool)",
      "function callPolicies(address,bytes4) view returns (bool,uint64,uint32,uint32,uint256,bytes32,bytes32)",
      "function setForcedCallPolicy(address,bytes4,bool,uint256,uint64,uint32,bytes32,bytes32)",
      "function executeForcedPolicy(address,uint256,bytes) payable returns (bytes)",
      "event CallPolicySet(address indexed target,bytes4 indexed selector,bool allowed,uint256 chainId,uint64 expiresAt,uint32 maxCalls,bytes32 calldataHash,bytes32 scopeHash)",
    ]);
    const managerInterface = new ethers.Interface([
      "function challenges(uint256) view returns (uint256,address,bytes32,uint256,uint64,uint64,bool,bool,bool,bytes32,string,bytes32)",
      "function challengeRevealInstanceHashOf(uint256) view returns (bytes32)",
      "function challengeInstanceHashOf(uint256) view returns (bytes32)",
      "event Challenged(uint256 indexed submissionId,address indexed challenger,bytes32 indexed reasonHash,uint256 bondWei,uint64 disputeEndsAt,bytes32 revealInstanceHash,bytes32 challengeInstanceHash)",
    ]);
    const outer = new ethers.Interface([
      "function depositChallenge(bytes challengeCalldata,uint256 bondWei,uint64 l2GasLimit)",
    ]).decodeFunctionData("depositChallenge", f.plan.deposits[1].calldata);
    const challengeInterface = new ethers.Interface([
      "function challenge(uint256 submissionId,bytes32 revealInstanceHash,bytes32 reasonHash)",
    ]);
    const challenge = challengeInterface.decodeFunctionData("challenge", outer.challengeCalldata);
    const portalInterface = new ethers.Interface([
      "event TransactionDeposited(address indexed from,address indexed to,uint256 indexed version,bytes opaqueData)",
    ]);
    const signedFor = (deposit, nonce, action, overrides = {}) => buildSignedTransactionRecord({
      wallet: f.signer,
      request: {
        to: deposit.to,
        data: deposit.calldata,
        value: BigInt(deposit.valueWei),
        chainId: 1,
        nonce,
        gasLimit: 200_000,
        maxFeePerGas: 2,
        maxPriorityFeePerGas: 1,
        type: 2,
        ...overrides,
      },
      chainId: 1,
      label: `censorship-fallback:${f.plan.calldataHash}:${action}`,
    });
    const policySigned = await signedFor(f.plan.deposits[0], 0, "policy");
    const challengeSigned = await signedFor(f.plan.deposits[1], 1, "challenge");
    const policyL1Hash = policySigned.hash;
    const challengeL1Hash = challengeSigned.hash;
    const policyTxHash = ethers.id("forced-policy-l2-tx");
    const challengeTxHash = ethers.id("forced-challenge-l2-tx");
    const blockHash = ethers.id("common-finalized-block");
    const challengedAt = 1_000_100n;
    const disputeEndsAt = 2_000_000n;
    const challengeInstanceHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "uint256", "uint256", "bytes32", "address", "bytes32", "uint64", "uint64"],
      [
        f.plan.challengeManager, BigInt(f.plan.l2ChainId), challenge.submissionId,
        challenge.revealInstanceHash, f.plan.wallet, challenge.reasonHash, challengedAt, disputeEndsAt,
      ],
    ));
    const portalEvent = portalInterface.encodeEventLog(portalInterface.getEvent("TransactionDeposited"), [
      f.plan.expectedForcedInclusionOwner, f.plan.wallet, 0, "0x",
    ]);
    const l1DepositLogs = {
      [policyL1Hash]: [{
        address: f.plan.portal, topics: portalEvent.topics, data: portalEvent.data, index: 7,
      }],
      [challengeL1Hash]: [{
        address: f.plan.portal, topics: portalEvent.topics, data: portalEvent.data, index: 8,
      }],
    };
    const sourceHash = (index) => ethers.keccak256(ethers.concat([
      ethers.ZeroHash,
      ethers.keccak256(ethers.concat([blockHash, ethers.zeroPadValue(ethers.toBeHex(index), 32)])),
    ]));

    const policyEvent = walletInterface.encodeEventLog(walletInterface.getEvent("CallPolicySet"), [
      f.plan.challengeManager,
      f.plan.selector,
      true,
      BigInt(f.plan.l2ChainId),
      BigInt(f.plan.policyExpiresAt),
      1,
      f.plan.calldataHash,
      f.plan.scopeHash,
    ]);
    const challengeEvent = managerInterface.encodeEventLog(managerInterface.getEvent("Challenged"), [
      challenge.submissionId,
      f.plan.wallet,
      challenge.reasonHash,
      BigInt(f.plan.bondWei),
      disputeEndsAt,
      challenge.revealInstanceHash,
      challengeInstanceHash,
    ]);
    const policyWalletData = walletInterface.encodeFunctionData("setForcedCallPolicy", [
      f.plan.challengeManager,
      f.plan.selector,
      true,
      BigInt(f.plan.l2ChainId),
      BigInt(f.plan.policyExpiresAt),
      1,
      f.plan.calldataHash,
      f.plan.scopeHash,
    ]);
    const challengeWalletData = walletInterface.encodeFunctionData("executeForcedPolicy", [
      f.plan.challengeManager,
      BigInt(f.plan.bondWei),
      outer.challengeCalldata,
    ]);
    const logs = {
      [f.plan.wallet.toLowerCase()]: [{
        address: f.plan.wallet,
        topics: policyEvent.topics,
        data: policyEvent.data,
        blockNumber: 500,
        blockHash,
        transactionHash: policyTxHash,
        index: 0,
      }],
      [f.plan.challengeManager.toLowerCase()]: [{
        address: f.plan.challengeManager,
        topics: challengeEvent.topics,
        data: challengeEvent.data,
        blockNumber: 500,
        blockHash,
        transactionHash: challengeTxHash,
        index: 1,
      }],
    };

    function fakeProvider(chainId, forcedFrom = f.plan.expectedForcedInclusionOwner, latest = null) {
      return {
        async getNetwork() { return { chainId: BigInt(chainId) }; },
        async getBlock(tag) {
          if (tag === "latest" && latest) return latest;
          return { number: 500, hash: blockHash, timestamp: 1_000_000 };
        },
        async getCode() { return code; },
        async call(request) {
          const to = request.to.toLowerCase();
          const selector = request.data.slice(0, 10);
          if (to === f.plan.l1Controller.toLowerCase()) {
            const values = {
              [controllerInterface.getFunction("portal").selector]: [f.plan.portal],
              [controllerInterface.getFunction("l2Wallet").selector]: [f.plan.wallet],
              [controllerInterface.getFunction("challengeManager").selector]: [f.plan.challengeManager],
              [controllerInterface.getFunction("challengeSelector").selector]: [f.plan.selector],
              [controllerInterface.getFunction("operator").selector]: [f.signer.address],
            };
            const fn = controllerInterface.getFunction(selector);
            return controllerInterface.encodeFunctionResult(fn, values[selector]);
          }
          if (to === f.plan.wallet.toLowerCase()) {
            if (selector === walletInterface.getFunction("forcedInclusionOwner").selector) {
              return walletInterface.encodeFunctionResult("forcedInclusionOwner", [f.plan.expectedForcedInclusionOwner]);
            }
            if (selector === walletInterface.getFunction("allowed").selector) {
              return walletInterface.encodeFunctionResult("allowed", [true]);
            }
            return walletInterface.encodeFunctionResult("callPolicies", [
              true,
              BigInt(f.plan.policyExpiresAt),
              1,
              0,
              BigInt(f.plan.l2ChainId),
              f.plan.calldataHash,
              f.plan.scopeHash,
            ]);
          }
          if (selector === managerInterface.getFunction("challengeRevealInstanceHashOf").selector) {
            return managerInterface.encodeFunctionResult("challengeRevealInstanceHashOf", [challenge.revealInstanceHash]);
          }
          if (selector === managerInterface.getFunction("challengeInstanceHashOf").selector) {
            return managerInterface.encodeFunctionResult("challengeInstanceHashOf", [challengeInstanceHash]);
          }
          return managerInterface.encodeFunctionResult("challenges", [
            challenge.submissionId,
            f.plan.wallet,
            challenge.reasonHash,
            BigInt(f.plan.bondWei),
            challengedAt,
            disputeEndsAt,
            false,
            false,
            false,
            ethers.ZeroHash,
            "",
            ethers.ZeroHash,
          ]);
        },
        async getLogs(request) { return logs[request.address.toLowerCase()] ?? []; },
        async getTransaction(hash) {
          return {
            hash,
            from: forcedFrom,
            to: f.plan.wallet,
            data: hash === policyTxHash ? policyWalletData : challengeWalletData,
            value: hash === policyTxHash ? 0n : BigInt(f.plan.bondWei),
            blockHash,
            type: "0x7e",
            sourceHash: sourceHash(hash === policyTxHash ? 7 : 8),
          };
        },
        async getTransactionReceipt(hash) {
          if (chainId === 1) {
            return { status: 1, blockHash, logs: l1DepositLogs[hash] ?? [] };
          }
          return {
            status: 1,
            blockHash,
            logs: hash === policyTxHash ? logs[f.plan.wallet.toLowerCase()] : logs[f.plan.challengeManager.toLowerCase()],
          };
        },
      };
    }

    function adapter(forcedFrom, latestPrimary = null, latestSecondary = null, readOnly = false) {
      return createEthersFallbackAdapter({
        l1Primary: fakeProvider(1),
        l1Secondary: fakeProvider(1),
        l2Primary: fakeProvider(8453, forcedFrom, latestPrimary),
        l2Secondary: fakeProvider(8453, forcedFrom, latestSecondary),
        ...(readOnly ? {
          operator: f.signer.address,
          l1GenesisHash: blockHash,
          l2GenesisHash: blockHash,
          l1Checkpoint: { blockNumber: 500, blockHash },
          l2Checkpoint: { blockNumber: 500, blockHash },
        } : { wallet: f.signer }),
        l1ChainId: 1,
        l2StartBlock: 0,
        gasLimit: 200_000,
        maxFeePerGas: 2,
        maxPriorityFeePerGas: 1,
        maxRpcHeadLagBlocks: 2,
        maxL2ScanBlocks: 1000,
        maxL2Logs: 10,
      });
    }

    const valid = adapter(f.plan.expectedForcedInclusionOwner);
    await valid.assertBindings(f.plan);
    await valid.assertDeadline(f.plan, "policy");
    const policyL1Anchor = { blockNumber: 500, blockHash, transactionHash: policyL1Hash };
    const challengeL1Anchor = { blockNumber: 500, blockHash, transactionHash: challengeL1Hash };
    const policyObservation = await valid.observePolicy(f.plan, policyL1Anchor);
    const challengeObservation = await valid.observeChallenge(f.plan, challengeL1Anchor);
    assert.equal(policyObservation.anchor.transactionHash, policyTxHash);
    assert.equal(challengeObservation.anchor.transactionHash, challengeTxHash);
    await valid.revalidateComplete({
      policy: {
        signedTransaction: policySigned,
        l1Anchor: policyL1Anchor,
        l2Anchor: policyObservation.anchor,
      },
      challenge: {
        signedTransaction: challengeSigned,
        l1Anchor: challengeL1Anchor,
        l2Anchor: challengeObservation.anchor,
      },
    }, f.plan);

    const executionPolicy = {
      l1GasLimit: "200000",
      maxFeePerGas: "2",
      maxPriorityFeePerGas: "1",
      maxRpcHeadLagBlocks: 2,
      maxL2ScanBlocks: 1000,
      maxL2Logs: 10,
    };
    const authorization = authorizationFor({ plan: f.plan, operator: f.signer.address, approver: f.approver });
    const completedState = {
      schema: "p42-censorship-fallback-run/v1",
      planHash: sha256Canonical(f.plan),
      l1ChainId: 1,
      l2ChainId: 8453,
      l2StartBlock: 0,
      controller: f.plan.l1Controller.toLowerCase(),
      executionPolicyHash: sha256Canonical(executionPolicy),
      authorizationHash: authorization.artifactHash,
      operator: f.signer.address.toLowerCase(),
      stage: "challenge_l2_confirmed",
      policy: {
        signedTransaction: policySigned,
        l1Anchor: policyL1Anchor,
        l2Anchor: policyObservation.anchor,
      },
      challenge: {
        signedTransaction: challengeSigned,
        l1Anchor: challengeL1Anchor,
        l2Anchor: challengeObservation.anchor,
      },
      createdAtUtc: "2026-07-14T00:00:00.000Z",
      updatedAtUtc: "2026-07-14T00:01:00.000Z",
    };
    const readOnly = adapter(f.plan.expectedForcedInclusionOwner, null, null, true);
    const verificationPolicy = {
      schema: "p42-censorship-fallback-verification-policy/v1",
      planHash: sha256Canonical(f.plan),
      releaseIndexDigest: `sha256:${"1".repeat(64)}`,
      deploymentManifestDigest: `sha256:${"2".repeat(64)}`,
      l1ChainId: 1,
      l2ChainId: 8453,
      l1GenesisHash: blockHash,
      l2GenesisHash: blockHash,
      l1Checkpoint: { blockNumber: 500, blockHash },
      l2Checkpoint: { blockNumber: 500, blockHash },
      controller: f.plan.l1Controller,
      controllerCodeHash: f.plan.l1ControllerCodeHash,
      portal: f.plan.portal,
      wallet: f.plan.wallet,
      challengeManager: f.plan.challengeManager,
      operator: f.signer.address,
      authorizationApprover: f.approver.address,
    };
    const report = await verifyCompletedFallbackRun({
      state: completedState,
      plan: f.plan,
      l1ChainId: 1,
      operator: f.signer.address,
      l2StartBlock: 0,
      adapter: readOnly,
      executionPolicy,
      authorization,
      authorizationApprover: f.approver.address,
      verificationPolicy,
      observedAtUtc: "2026-07-14T00:02:00.000Z",
    });
    assert.equal(report.status, "verified");
    assert.equal(report.policy.signedTransactionHash, policyL1Hash);
    assert.equal(report.challenge.signedTransactionHash, challengeL1Hash);
    assert.equal(report.sequencerCensorshipClaimed, false);
    assert.equal(report.gate3Closed, false);
    const { verificationHash, ...reportBody } = report;
    assert.equal(verificationHash, sha256Canonical(reportBody));
    const excessiveFeeRecord = await signedFor(f.plan.deposits[0], 0, "policy", {
      maxFeePerGas: 3,
    });
    await assert.rejects(
      verifyCompletedFallbackRun({
        state: {
          ...completedState,
          policy: { ...completedState.policy, signedTransaction: excessiveFeeRecord },
        },
        plan: f.plan,
        l1ChainId: 1,
        operator: f.signer.address,
        l2StartBlock: 0,
        adapter: readOnly,
        executionPolicy,
        authorization,
        authorizationApprover: f.approver.address,
        verificationPolicy,
        observedAtUtc: "2026-07-14T00:02:00.000Z",
      }),
      /changes the authorized fee envelope/,
    );
    await assert.rejects(
      readOnly.sign("policy", {}, f.plan, 0),
      /read-only adapter cannot sign/,
    );
    await assert.rejects(
      verifyCompletedFallbackRun({
        state: { ...completedState, stage: "challenge_l1_final" },
        plan: f.plan,
        l1ChainId: 1,
        operator: f.signer.address,
        l2StartBlock: 0,
        adapter: readOnly,
        executionPolicy,
        authorization,
        authorizationApprover: f.approver.address,
        verificationPolicy,
        observedAtUtc: "2026-07-14T00:02:00.000Z",
      }),
      /requires a completed journal/,
    );
    await assert.rejects(
      verifyCompletedFallbackRun({
        state: {
          ...completedState,
          policy: { ...completedState.policy, signedTransaction: { hash: policyL1Hash } },
        },
        plan: f.plan,
        l1ChainId: 1,
        operator: f.signer.address,
        l2StartBlock: 0,
        adapter: readOnly,
        executionPolicy,
        authorization,
        authorizationApprover: f.approver.address,
        verificationPolicy,
        observedAtUtc: "2026-07-14T00:02:00.000Z",
      }),
      /signed transaction journal has an unsupported schema/,
    );
    await assert.rejects(
      verifyCompletedFallbackRun({
        state: completedState,
        plan: f.plan,
        l1ChainId: 1,
        operator: f.signer.address,
        l2StartBlock: 0,
        adapter: readOnly,
        executionPolicy,
        authorization,
        authorizationApprover: f.approver.address,
        verificationPolicy: { ...verificationPolicy, l1GenesisHash: ethers.id("wrong-genesis") },
        observedAtUtc: "2026-07-14T00:02:00.000Z",
      }),
      /adapter identity mismatch/,
    );

    const wrongSender = adapter(ethers.Wallet.createRandom().address);
    await assert.rejects(
      () => wrongSender.observePolicy(f.plan, policyL1Anchor),
      /not emitted by the forced controller deposit/,
    );
    const current = { number: 501, hash: ethers.id("current"), timestamp: 1_900_000 };
    const lagging = { number: 500, hash: blockHash, timestamp: 1_000_000 };
    await assert.rejects(
      adapter(f.plan.expectedForcedInclusionOwner, current, lagging).assertDeadline(f.plan, "policy"),
      /deadline slack is 0s/,
    );
    await assert.rejects(
      adapter(f.plan.expectedForcedInclusionOwner, { ...current, number: 510 }, lagging)
        .assertDeadline(f.plan, "policy"),
      /exceed the permitted lag/,
    );
  });

  it("resumes the same signed bytes after restart instead of allocating a replacement", async () => {
    const f = fixture();
    const firstAdapter = fakeAdapter(f.signer);
    await advance(f, firstAdapter);
    const firstHash = JSON.parse(readFileSync(f.statePath, "utf8")).policy.signedTransaction.hash;

    const restarted = fakeAdapter(f.signer);
    // The replacement adapter sees its first reconciliation as pending; no new
    // signature is created because the journaled raw bytes remain authoritative.
    assert.equal((await advance(f, restarted)).stage, "policy_broadcast");
    assert.deepEqual(restarted.signed, []);
    assert.equal(JSON.parse(readFileSync(f.statePath, "utf8")).policy.signedTransaction.hash, firstHash);
  });

  it("revalidates finalized policy immediately before phase-two signing", async () => {
    const f = fixture();
    const adapter = fakeAdapter(f.signer, { policyUnavailableAfterFirst: true });
    await advance(f, adapter);
    assert.equal((await advance(f, adapter)).stage, "policy_l2_confirmed");
    await assert.rejects(advance(f, adapter), /policy is not finalized immediately before signing/);
    const disk = JSON.parse(readFileSync(f.statePath, "utf8"));
    assert.equal(disk.challenge.signedTransaction, null);
  });

  it("fails closed on journal tampering and exhausted deadline before challenge signing", async () => {
    const f = fixture();
    const adapter = fakeAdapter(f.signer);
    await advance(f, adapter);
    const state = JSON.parse(readFileSync(f.statePath, "utf8"));
    state.planHash = ethers.id("replacement-plan");
    writeFileSync(f.statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    await assert.rejects(() => advance(f, adapter), /journal identity is invalid/);

    const g = fixture();
    const deadlineAdapter = fakeAdapter(g.signer, { stopDeadlineAfterPolicy: true });
    await advance(g, deadlineAdapter);
    await advance(g, deadlineAdapter);
    await assert.rejects(() => advance(g, deadlineAdapter), /deadline slack exhausted/);
    assert.deepEqual(deadlineAdapter.signed, ["policy"]);
  });
});
