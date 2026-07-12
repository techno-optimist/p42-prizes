import assert from "node:assert/strict";
import { test } from "node:test";
import { chmodSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ethers } from "ethers";

import {
  activationRequest,
  collectFundingActivationSnapshot,
  nextFundingActivationAction,
  signAndBroadcastActivationAction,
} from "./funding-activation-executor.mjs";

const digest = `sha256:${"a".repeat(64)}`;
const chainDigest = `0x${"a".repeat(64)}`;
const ZERO_HASH = `0x${"0".repeat(64)}`;
const address = (value) => ethers.getAddress(`0x${value.toString(16).padStart(40, "0")}`);

function plan() {
  const treasury = address(1);
  const governanceSigners = [address(2), address(3), address(4)];
  const timelock = address(5);
  const operations = [];
  const boards = Array.from({ length: 10 }, (_, index) => ({
    problemId: index + 1,
    submissions: address(100 + index * 2),
    pool: address(101 + index * 2),
  }));
  for (const board of boards) operations.push({
    sequence: operations.length + 1, authority: "treasury", label: `board.${board.problemId}.authorizeFunding`,
    problemId: board.problemId, to: board.submissions, value: "0", data: `0x${"1".repeat(8)}${"a".repeat(64)}`,
  });
  const authorizationLabels = operations.map((row) => row.label);
  for (const board of boards) {
    const label = `board.${board.problemId}.armFunding`;
    const data = `0x${"2".repeat(8)}${"a".repeat(64)}`;
    const salt = ethers.id(`${digest}:${label}`);
    operations.push({
      sequence: operations.length + 1, authority: "governance", label, problemId: board.problemId,
      to: board.submissions, value: "0", data, salt,
      operationId: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [board.submissions, 0n, data, salt])),
      dependsOn: authorizationLabels,
    });
  }
  const armLabels = operations.slice(10).map((row) => row.label);
  for (const board of boards) {
    const label = `board.${board.problemId}.setAcceptingFunds`;
    const data = `0x${"3".repeat(8)}${"0".repeat(63)}1`;
    const salt = ethers.id(`${digest}:${label}`);
    operations.push({
      sequence: operations.length + 1, authority: "governance", label, problemId: board.problemId,
      to: board.pool, value: "0", data, salt,
      operationId: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [board.pool, 0n, data, salt])),
      dependsOn: armLabels,
    });
  }
  return {
    schema: "p42-funding-activation-plan/v1", planDigest: `sha256:${"b".repeat(64)}`,
    chainId: 84532, boardCount: 10, authorizationDigest: digest,
    authorizationExpiresAt: 2_000_000_000, treasury, timelock,
    governanceSigners, governanceThreshold: 2, governanceDelaySeconds: 3600,
    operations,
  };
}

function snapshot(inputPlan) {
  const timelockOperations = {};
  for (const operation of inputPlan.operations.slice(10)) {
    timelockOperations[operation.operationId.toLowerCase()] = {
      state: 0, eta: 0n, expiresAt: 0n, confirmedBy: [],
    };
  }
  return {
    chainId: inputPlan.chainId, planDigest: inputPlan.planDigest, now: 1_900_000_000n,
    boards: Array.from({ length: 10 }, (_, index) => ({
      problemId: index + 1, authorizedFundingDigest: `0x${"0".repeat(64)}`,
      fundingAuthorizationExpiresAt: 0n, fundingArmed: false,
      fundingAuthorizationDigest: `0x${"0".repeat(64)}`, acceptingFunds: false,
    })),
    timelockOperations,
  };
}

test("executor enforces global authorize and arm barriers", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  let action = nextFundingActivationAction(inputPlan, state);
  assert.equal(action.kind, "authorize");
  assert.equal(action.operation.problemId, 1);

  for (const board of state.boards) {
    board.authorizedFundingDigest = chainDigest;
    board.fundingAuthorizationExpiresAt = BigInt(inputPlan.authorizationExpiresAt);
  }
  action = nextFundingActivationAction(inputPlan, state);
  assert.equal(action.kind, "schedule");
  assert.match(action.operation.label, /armFunding$/);
  const armState = state.timelockOperations[action.operation.operationId.toLowerCase()];
  armState.state = 1; armState.eta = state.now + 3600n; armState.confirmedBy = [inputPlan.governanceSigners[0]];
  action = nextFundingActivationAction(inputPlan, state);
  assert.equal(action.kind, "confirm");
  assert.equal(action.signer, inputPlan.governanceSigners[1]);
  armState.confirmedBy.push(inputPlan.governanceSigners[1]);
  action = nextFundingActivationAction(inputPlan, state);
  assert.equal(action.kind, "wait");
  state.now = armState.eta;
  action = nextFundingActivationAction(inputPlan, state);
  assert.equal(action.kind, "execute");

  state.timelockOperations[inputPlan.operations[20].operationId.toLowerCase()].state = 1;
  assert.throws(() => nextFundingActivationAction(inputPlan, state), /before the global arm barrier/);
});

test("executor reaches pool opening only after every finalized arm", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  for (const board of state.boards) {
    board.authorizedFundingDigest = chainDigest;
    board.fundingAuthorizationExpiresAt = BigInt(inputPlan.authorizationExpiresAt);
    board.fundingArmed = true;
    board.fundingAuthorizationDigest = chainDigest;
  }
  for (const operation of inputPlan.operations.slice(10, 20)) {
    state.timelockOperations[operation.operationId.toLowerCase()].state = 2;
  }
  const action = nextFundingActivationAction(inputPlan, state);
  assert.equal(action.kind, "schedule");
  assert.match(action.operation.label, /setAcceptingFunds$/);
});

test("signing revalidates the exact plan and journals raw bytes before broadcast", async () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  const action = nextFundingActivationAction(inputPlan, state);
  const signer = ethers.Wallet.createRandom();
  const wallet = {
    address: signer.address,
    provider: {},
    signingKey: signer.signingKey,
    populateTransaction: async (request) => ({ ...request, nonce: 0, gasLimit: 100_000n, gasPrice: 1n }),
    signTransaction: (request) => signer.signTransaction(request),
  };
  inputPlan.treasury = signer.address;
  action.signer = signer.address;
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-executor-")));
  chmodSync(root, 0o700);
  let observedRecord;
  const receipt = await signAndBroadcastActivationAction({
    plan: inputPlan, action, wallet, journalRoot: root,
    journalPath: join(root, "journal.json"), revalidate: async () => inputPlan,
    currentTimestamp: async () => 1_900_000_000n,
    transactionReconciler: async (_provider, record) => {
      observedRecord = record;
      return { status: "receipt", receipt: { status: 1, blockNumber: 9, blockHash: `0x${"9".repeat(64)}` } };
    },
  });
  assert.equal(receipt.receipt.status, 1);
  assert.ok(observedRecord.raw_tx.startsWith("0x"));
  assert.equal(ethers.Transaction.from(observedRecord.raw_tx).to, activationRequest(inputPlan, action).to);
});

test("dual-RPC snapshot uses one common finalized block and rejects disagreement", async () => {
  const inputPlan = plan();
  const code = "0x6000";
  const codeHash = ethers.keccak256(code);
  inputPlan.timelockRuntimeCodeHash = codeHash;
  for (const operation of inputPlan.operations) operation.expectedRuntimeCodeHash = codeHash;
  const selector = (signature) => ethers.id(signature).slice(0, 10);
  const selectors = {
    authorized: selector("authorizedFundingDigest()"), expires: selector("fundingAuthorizationExpiresAt()"),
    armed: selector("fundingArmed()"), consumed: selector("fundingAuthorizationDigest()"),
    accepting: selector("acceptingFunds()"), state: selector("stateOf(bytes32)"),
    ops: selector("ops(bytes32)"), confirmed: selector("confirmedBy(bytes32,address)"),
  };
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const provider = (timestamp = 1_900_000_000) => ({
    getNetwork: async () => ({ chainId: 84532n }),
    getBlock: async (tag) => ({ number: tag === "finalized" ? 50 : Number(tag), hash: `0x${"5".repeat(64)}`, timestamp }),
    getCode: async () => code,
    send: async (method, [{ data }, blockTag]) => {
      assert.equal(method, "eth_call");
      assert.equal(blockTag, "0x32");
      const id = data.slice(0, 10);
      if (id === selectors.authorized || id === selectors.consumed) return coder.encode(["bytes32"], [ZERO_HASH]);
      if (id === selectors.expires) return coder.encode(["uint64"], [0]);
      if (id === selectors.armed || id === selectors.accepting || id === selectors.confirmed) return coder.encode(["bool"], [false]);
      if (id === selectors.state) return coder.encode(["uint8"], [0]);
      if (id === selectors.ops) return coder.encode(["uint64", "uint64", "uint32", "uint32", "uint8", "bool", "bytes32"], [0, 0, 0, 0, 0, false, ZERO_HASH]);
      throw new Error(`unexpected selector ${id}`);
    },
  });
  const snapshot = await collectFundingActivationSnapshot(inputPlan, provider(), provider());
  assert.equal(snapshot.blockNumber, 50);
  assert.equal(snapshot.boards.length, 10);
  await assert.rejects(() => collectFundingActivationSnapshot(inputPlan, provider(), provider(1_900_000_001)), /disagree/);
});

test("expired chain time is rejected before any signature is created", async () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  const action = nextFundingActivationAction(inputPlan, state);
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address;
  action.signer = signer.address;
  let signed = false;
  const wallet = {
    address: signer.address, provider: {},
    signingKey: signer.signingKey,
    populateTransaction: async (request) => ({ ...request, nonce: 0, gasLimit: 100_000n, gasPrice: 1n }),
    signTransaction: async (request) => { signed = true; return signer.signTransaction(request); },
  };
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-expired-")));
  chmodSync(root, 0o700);
  await assert.rejects(() => signAndBroadcastActivationAction({
    plan: inputPlan, action, wallet, journalRoot: root, journalPath: join(root, "journal.json"),
    revalidate: async () => inputPlan,
    currentTimestamp: async () => BigInt(inputPlan.authorizationExpiresAt) + 1n,
  }), /before authorization expiry|after authorization expiry/);
  assert.equal(signed, false);
});

test("expiry during validator execution is rejected before signing", async () => {
  const inputPlan = plan();
  const action = nextFundingActivationAction(inputPlan, snapshot(inputPlan));
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address; action.signer = signer.address;
  let signed = false; let timeReads = 0;
  const wallet = {
    address: signer.address, provider: {},
    signingKey: signer.signingKey,
    populateTransaction: async (request) => ({ ...request, nonce: 0, gasLimit: 100_000n, gasPrice: 1n }),
    signTransaction: async (request) => { signed = true; return signer.signTransaction(request); },
  };
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-expiring-")));
  chmodSync(root, 0o700);
  await assert.rejects(() => signAndBroadcastActivationAction({
    plan: inputPlan, action, wallet, journalRoot: root, journalPath: join(root, "journal.json"),
    revalidate: async () => inputPlan,
    currentTimestamp: async () => (++timeReads === 1
      ? BigInt(inputPlan.authorizationExpiresAt) - 1n
      : BigInt(inputPlan.authorizationExpiresAt) + 1n),
  }), /expired during pre-sign/);
  assert.equal(signed, false);
});

test("expiry during transaction population is rejected before raw signing", async () => {
  const inputPlan = plan();
  const action = nextFundingActivationAction(inputPlan, snapshot(inputPlan));
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address; action.signer = signer.address;
  let signed = false; let timeReads = 0;
  const wallet = {
    address: signer.address, provider: {},
    signingKey: { sign: (value) => { signed = true; return signer.signingKey.sign(value); } },
    populateTransaction: async (request) => ({ ...request, nonce: 0, gasLimit: 100_000n, gasPrice: 1n }),
  };
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-populate-")));
  chmodSync(root, 0o700);
  await assert.rejects(() => signAndBroadcastActivationAction({
    plan: inputPlan, action, wallet, journalRoot: root, journalPath: join(root, "journal.json"),
    revalidate: async () => inputPlan,
    currentTimestamp: async () => (++timeReads < 3
      ? BigInt(inputPlan.authorizationExpiresAt) - 1n
      : BigInt(inputPlan.authorizationExpiresAt) + 1n),
  }), /expired during transaction population/);
  assert.equal(signed, false);
});
