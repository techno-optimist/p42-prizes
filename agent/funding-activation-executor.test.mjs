import assert from "node:assert/strict";
import { test } from "node:test";
import { chmodSync, mkdtempSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ethers } from "ethers";
import { createHash } from "node:crypto";
import { canonicalJson } from "./lib.mjs";

import {
  activationRequest,
  buildFundingActivationCompletion,
  collectActivationNonceEvidence,
  collectFundingActivationSnapshot,
  destroyFundingActivationOperationProviders,
  fundingActivationCompletionAnchor,
  nextFundingActivationAction,
  prepareActivationSigningRequest,
  reconcileFundingActivationConfirmations,
  signAndBroadcastActivationAction,
  validateFundingActivationOperationObservations,
} from "./funding-activation-executor.mjs";
import * as activationExecutorModule from "./funding-activation-executor.mjs";

const digest = `sha256:${"a".repeat(64)}`;
const chainDigest = `0x${"a".repeat(64)}`;
const ZERO_HASH = `0x${"0".repeat(64)}`;
const address = (value) => ethers.getAddress(`0x${value.toString(16).padStart(40, "0")}`);
const rpcAuthority = () => ({
  schema: "p42-activation-rpc-authority/v1", registryDigest: `sha256:${"9".repeat(64)}`,
  primary: { operatorId: "operator-primary", endpointOrigin: "https://primary.example", endpointProfileDigest: `sha256:${"8".repeat(64)}` },
  secondary: { operatorId: "operator-secondary", endpointOrigin: "https://secondary.example", endpointProfileDigest: `sha256:${"7".repeat(64)}` },
});
const observedRpcAuthority = () => ({
  ...rpcAuthority(),
  primary: { ...rpcAuthority().primary, observedRawChainId: "0x14a34" },
  secondary: { ...rpcAuthority().secondary, observedRawChainId: "0x14a34" },
});
const submissionsInterface = new ethers.Interface([
  "function authorizeFunding(bytes32 authorizationDigest,uint64 expiresAt,uint256 nonce,bytes[3] signatures)",
  "function armFunding(bytes32 authorizationDigest)",
]);
const poolInterface = new ethers.Interface(["function setAcceptingFunds(bool accepting)"]);

test("operation evidence cleanup attempts both provider destroys when one throws", async () => {
  const destroyed = [];
  await destroyFundingActivationOperationProviders(
    {
      destroy() {
        destroyed.push("primary");
        throw new Error("primary cleanup failed");
      },
    },
    { destroy() { destroyed.push("secondary"); } },
  );
  assert.deepEqual(destroyed.sort(), ["primary", "secondary"]);
});

function nonceEvidence(currentNonce = 0, finalizedNonce = currentNonce) {
  return async (signer) => ({
    schema: "p42-funding-activation-nonce-evidence/v1",
    signer: ethers.getAddress(signer).toLowerCase(),
    finalizedBlockNumber: 40,
    finalizedBlockHash: `0x${"4".repeat(64)}`,
    finalizedNonce,
    currentBlockNumber: 50,
    currentBlockHash: `0x${"5".repeat(64)}`,
    currentNonce,
  });
}

function plan() {
  const treasury = address(1);
  const governanceSigners = [address(2), address(3), address(4)];
  const timelock = address(5);
  const operations = [];
  const runtimeCodeHash = `0x${"6".repeat(64)}`;
  const boards = Array.from({ length: 10 }, (_, index) => ({
    problemId: index + 1,
    submissions: address(100 + index * 2),
    pool: address(101 + index * 2),
  }));
  for (const [boardIndex, board] of boards.entries()) operations.push({
    sequence: operations.length + 1, authority: "treasury", label: `board.${board.problemId}.authorizeFunding`,
    boardIndex, problemId: board.problemId, to: board.submissions, expectedRuntimeCodeHash: runtimeCodeHash, value: "0",
    authorizationNonce: "0", verifiedSignatureCount: 3,
    data: submissionsInterface.encodeFunctionData("authorizeFunding", [chainDigest, 2_000_000_000, 0n, Array(3).fill(`0x${"1".repeat(130)}`)]),
    dependsOn: [],
  });
  const authorizationLabels = operations.map((row) => row.label);
  for (const [boardIndex, board] of boards.entries()) {
    const label = `board.${board.problemId}.armFunding`;
    const data = submissionsInterface.encodeFunctionData("armFunding", [chainDigest]);
    const salt = ethers.id(`${digest}:${label}`);
    operations.push({
      sequence: operations.length + 1, authority: "governance", label, boardIndex, problemId: board.problemId,
      to: board.submissions, value: "0", data, salt,
      expectedRuntimeCodeHash: runtimeCodeHash,
      operationId: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [board.submissions, 0n, data, salt])),
      dependsOn: authorizationLabels,
    });
  }
  const armLabels = operations.slice(10).map((row) => row.label);
  for (const [boardIndex, board] of boards.entries()) {
    const label = `board.${board.problemId}.setAcceptingFunds`;
    const data = poolInterface.encodeFunctionData("setAcceptingFunds", [true]);
    const salt = ethers.id(`${digest}:${label}`);
    operations.push({
      sequence: operations.length + 1, authority: "governance", label, boardIndex, problemId: board.problemId,
      to: board.pool, value: "0", data, salt,
      expectedRuntimeCodeHash: runtimeCodeHash,
      operationId: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes", "bytes32"], [board.pool, 0n, data, salt])),
      dependsOn: armLabels,
    });
  }
  return {
    schema: "p42-funding-activation-plan/v2", planDigest: `sha256:${"b".repeat(64)}`,
    chainId: 84532, network: "base-sepolia", boardCount: 10, authorizationDigest: digest,
    manifestBytesDigest: `sha256:${"c".repeat(64)}`, deploymentCommit: "d".repeat(40),
    authorizationBytesDigest: `sha256:${"7".repeat(64)}`,
    dependencySecurityReportDigest: `sha256:${"8".repeat(64)}`,
    rpcAuthority: rpcAuthority(),
    deploymentConfigHash: `0x${"e".repeat(64)}`, releaseBindingDigest: `sha256:${"f".repeat(64)}`,
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
    rpcAuthority: observedRpcAuthority(),
    boards: Array.from({ length: 10 }, (_, index) => ({
      problemId: index + 1, authorizedFundingDigest: `0x${"0".repeat(64)}`,
      fundingAuthorizationExpiresAt: 0n, fundingAuthorizationNonce: 0n,
      fundingAuthorizationVerified: false, fundingArmed: false,
      fundingAuthorizationDigest: `0x${"0".repeat(64)}`, acceptingFunds: false,
    })),
    timelockOperations,
  };
}

async function legacyTransaction(inputPlan, action, signer, nonce, status) {
  const request = activationRequest(inputPlan, action);
  const rawTx = await signer.signTransaction({
    ...request, nonce, gasLimit: 100_000n, gasPrice: 1n,
  });
  const transaction = ethers.Transaction.from(rawTx);
  const record = {
    schema_version: "p42-signed-transaction/v1",
    label: `${action.operation.label}.${action.kind}.${signer.address.toLowerCase()}`,
    signer: signer.address.toLowerCase(), hash: ethers.keccak256(rawTx), raw_tx: rawTx,
    chain_id: inputPlan.chainId, nonce: transaction.nonce, to: transaction.to.toLowerCase(),
    value: transaction.value.toString(), data_hash: ethers.keccak256(transaction.data),
    signed_at_utc: "2026-07-12T12:00:00.000Z", status,
  };
  if (status === "broadcast") record.broadcastAtUtc = "2026-07-12T12:01:00.000Z";
  if (status === "mined") {
    record.blockNumber = 123;
    record.blockHash = `0x${"8".repeat(64)}`;
  }
  return record;
}

function writeLegacyJournal(root, inputPlan, transactions) {
  const journalPath = join(root, "journal.json");
  writeFileSync(journalPath, `${JSON.stringify({
    schema: "p42-funding-activation-journal/v1",
    planDigest: inputPlan.planDigest,
    authorizationDigest: inputPlan.authorizationDigest,
    authorizationExpiresAt: inputPlan.authorizationExpiresAt,
    chainId: inputPlan.chainId,
    generation: 7,
    transactions,
  }, null, 2)}\n`, { mode: 0o600 });
  return journalPath;
}

test("v1 journals migrate signed, broadcast, and mined records into exact v2 signing requests", async () => {
  const inputPlan = plan();
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address;
  const transactions = {};
  const actions = inputPlan.operations.slice(0, 3).map((operation) => ({
    kind: "authorize", operation, signer: signer.address,
  }));
  for (const [index, status] of ["signed", "broadcast", "mined"].entries()) {
    const record = await legacyTransaction(inputPlan, actions[index], signer, index, status);
    transactions[record.label] = record;
  }
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-migrate-")));
  chmodSync(root, 0o700);
  const journalPath = writeLegacyJournal(root, inputPlan, transactions);

  const request = await prepareActivationSigningRequest({
    plan: inputPlan, action: actions[0], signer: null, journalRoot: root, journalPath,
    revalidate: async () => { throw new Error("migration must not create a new request"); },
    currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(0),
  });

  const migrated = JSON.parse(readFileSync(journalPath, "utf8"));
  assert.equal(migrated.schema, "p42-funding-activation-journal/v2");
  assert.equal(migrated.generation, 8);
  assert.deepEqual(migrated.transactions, transactions);
  assert.equal(Object.keys(migrated.signingRequests).length, 3);
  assert.equal(request.createdAtUtc, transactions[request.label].signed_at_utc);
  for (const action of actions) {
    const label = `${action.operation.label}.${action.kind}.${signer.address.toLowerCase()}`;
    const transaction = ethers.Transaction.from(transactions[label].raw_tx);
    assert.equal(migrated.signingRequests[label].unsignedTransaction, transaction.unsignedSerialized);
    assert.equal(migrated.signingRequests[label].unsignedHash, transaction.unsignedHash);
  }
  assert.equal(statSync(journalPath).mode & 0o777, 0o600);
});

test("v1 journal migration rejects tampered transaction records without rewriting", async () => {
  const inputPlan = plan();
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address;
  const action = { kind: "authorize", operation: inputPlan.operations[0], signer: signer.address };
  const record = await legacyTransaction(inputPlan, action, signer, 0, "broadcast");
  record.data_hash = `0x${"f".repeat(64)}`;
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-migrate-tamper-")));
  chmodSync(root, 0o700);
  const journalPath = writeLegacyJournal(root, inputPlan, { [record.label]: record });
  const before = readFileSync(journalPath);

  await assert.rejects(() => prepareActivationSigningRequest({
    plan: inputPlan, action, signer: null, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(0),
  }), /tampered or has no exact plan binding/);
  assert.deepEqual(readFileSync(journalPath), before);
});

test("v1 journal migration rejects ambiguous plan bindings without rewriting", async () => {
  const inputPlan = plan();
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address;
  const operation = inputPlan.operations[0];
  inputPlan.operations[1] = { ...operation, sequence: 2 };
  const action = { kind: "authorize", operation, signer: signer.address };
  const record = await legacyTransaction(inputPlan, action, signer, 0, "mined");
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-migrate-ambiguous-")));
  chmodSync(root, 0o700);
  const journalPath = writeLegacyJournal(root, inputPlan, { [record.label]: record });
  const before = readFileSync(journalPath);

  await assert.rejects(() => prepareActivationSigningRequest({
    plan: inputPlan, action, signer: null, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(0),
  }), /ambiguous plan binding|problem IDs must be unique/);
  assert.deepEqual(readFileSync(journalPath), before);
});

test("executor enforces global authorize and arm barriers", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  let action = nextFundingActivationAction(inputPlan, state);
  assert.equal(action.kind, "authorize");
  assert.equal(action.operation.problemId, 1);

  for (const board of state.boards) {
    board.authorizedFundingDigest = chainDigest;
    board.fundingAuthorizationExpiresAt = BigInt(inputPlan.authorizationExpiresAt);
    board.fundingAuthorizationNonce = 1n;
    board.fundingAuthorizationVerified = true;
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

test("executor rejects protocol state that crossed the global authorization barrier out of plan", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  state.boards[0].fundingArmed = true;
  state.boards[0].fundingAuthorizationDigest = chainDigest;
  state.boards[0].acceptingFunds = true;
  assert.throws(
    () => nextFundingActivationAction(inputPlan, state),
    /before the global authorization barrier/,
  );
});

test("executor fails closed on legacy activation plans", () => {
  const inputPlan = plan();
  inputPlan.schema = "p42-funding-activation-plan/v1";
  assert.throws(() => nextFundingActivationAction(inputPlan, snapshot(inputPlan)), /validated activation plan/);
});

test("executor rejects prefixed, duplicated, and rederived operation topology", () => {
  for (const mutate of [
    (inputPlan) => { inputPlan.operations[0].label = `prefix.${inputPlan.operations[0].label}`; },
    (inputPlan) => { inputPlan.operations[1] = { ...inputPlan.operations[0], sequence: 2, boardIndex: 1 }; },
    (inputPlan) => { inputPlan.operations[10].operationId = inputPlan.operations[11].operationId; },
  ]) {
    const inputPlan = plan();
    mutate(inputPlan);
    assert.throws(() => nextFundingActivationAction(inputPlan, snapshot(inputPlan)), /topology|operation|unique|derived/);
  }
});

test("executor reaches pool opening only after every finalized arm", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  for (const board of state.boards) {
    board.authorizedFundingDigest = chainDigest;
    board.fundingAuthorizationExpiresAt = BigInt(inputPlan.authorizationExpiresAt);
    board.fundingAuthorizationNonce = 1n;
    board.fundingAuthorizationVerified = true;
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

test("executor rejects alternate-salt state when exact plan operations remain None", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  for (const board of state.boards) {
    board.authorizedFundingDigest = chainDigest;
    board.fundingAuthorizationExpiresAt = BigInt(inputPlan.authorizationExpiresAt);
    board.fundingAuthorizationNonce = 1n;
    board.fundingAuthorizationVerified = true;
    board.fundingArmed = true;
    board.fundingAuthorizationDigest = chainDigest;
    board.acceptingFunds = true;
  }
  const alternateOperationId = `0x${"f".repeat(64)}`;
  state.timelockOperations[alternateOperationId] = {
    state: 2, eta: 0n, expiresAt: 0n, confirmedBy: inputPlan.governanceSigners.slice(0, 2),
  };
  assert.throws(
    () => nextFundingActivationAction(inputPlan, state),
    /outside its exact plan-bound operation/,
  );
});

test("executor validates later out-of-plan arms before selecting an earlier pending operation", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  for (const board of state.boards) {
    board.authorizedFundingDigest = chainDigest;
    board.fundingAuthorizationExpiresAt = BigInt(inputPlan.authorizationExpiresAt);
    board.fundingAuthorizationNonce = 1n;
    board.fundingAuthorizationVerified = true;
  }
  state.boards[1].fundingArmed = true;
  state.boards[1].fundingAuthorizationDigest = chainDigest;
  state.timelockOperations[`0x${"e".repeat(64)}`] = {
    state: 2, eta: 0n, expiresAt: 0n, confirmedBy: inputPlan.governanceSigners.slice(0, 2),
  };
  assert.throws(
    () => nextFundingActivationAction(inputPlan, state),
    /outside its exact plan-bound operation/,
  );
});

test("completion rejects all-open state when all exact operations are None", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  for (const board of state.boards) {
    board.authorizedFundingDigest = chainDigest;
    board.fundingAuthorizationExpiresAt = BigInt(inputPlan.authorizationExpiresAt);
    board.fundingAuthorizationNonce = 1n;
    board.fundingAuthorizationVerified = true;
    board.fundingArmed = true;
    board.fundingAuthorizationDigest = chainDigest;
    board.acceptingFunds = true;
  }
  state.blockNumber = 42;
  state.blockHash = `0x${"4".repeat(64)}`;
  assert.throws(
    () => buildFundingActivationCompletion(inputPlan, state),
    /outside its exact plan-bound operation/,
  );
});

test("signing revalidates the exact plan and journals raw bytes before broadcast", async () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  const action = nextFundingActivationAction(inputPlan, state);
  const signer = ethers.Wallet.createRandom();
  const wallet = {
    getAddress: async () => signer.address,
    provider: {},
    populateTransaction: async (request) => ({ ...request, nonce: 0, gasLimit: 100_000n, gasPrice: 1n }),
    signTransaction: (request) => signer.signTransaction(request),
  };
  inputPlan.treasury = signer.address;
  action.signer = signer.address;
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-executor-")));
  chmodSync(root, 0o700);
  const journalPath = join(root, "journal.json");
  const signingRequest = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: wallet, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(0),
  });
  assert.match(signingRequest.unsignedHash, /^0x[0-9a-f]{64}$/);
  let observedRecord;
  const receipt = await signAndBroadcastActivationAction({
    plan: inputPlan, action, wallet, journalRoot: root,
    journalPath, revalidate: async () => inputPlan,
    currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(0),
    transactionReconciler: async (_provider, record) => {
      observedRecord = record;
      return { status: "receipt", receipt: { status: 1, blockNumber: 9, blockHash: `0x${"9".repeat(64)}` } };
    },
  });
  assert.equal(receipt.receipt.status, 1);
  assert.ok(observedRecord.raw_tx.startsWith("0x"));
  assert.equal(ethers.Transaction.from(observedRecord.raw_tx).to, activationRequest(inputPlan, action).to);
  assert.equal("address" in wallet, false);
  assert.equal("signingKey" in wallet, false);
});

test("a late security-gate block makes broadcast unreachable for new and journaled transactions", async () => {
  const inputPlan = plan();
  const action = nextFundingActivationAction(inputPlan, snapshot(inputPlan));
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address;
  action.signer = signer.address;
  const wallet = {
    getAddress: async () => signer.address,
    provider: {},
    populateTransaction: async (request) => ({ ...request, nonce: 0, gasLimit: 100_000n, gasPrice: 1n }),
    signTransaction: (request) => signer.signTransaction(request),
  };
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-gate-block-")));
  chmodSync(root, 0o700);
  const journalPath = join(root, "journal.json");
  await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: wallet, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(0),
  });
  let validations = 0;
  let broadcasts = 0;
  const run = () => signAndBroadcastActivationAction({
    plan: inputPlan, action, wallet, journalRoot: root, journalPath,
    revalidate: async () => {
      validations += 1;
      if (validations >= 2) throw new Error("SP1 dependency security gate blocks production launch authorization");
      return inputPlan;
    },
    currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(0),
    transactionReconciler: async () => {
      broadcasts += 1;
      return { status: "pending", transaction: {} };
    },
  });
  await assert.rejects(run, /SP1 dependency security gate blocks/);
  assert.equal(broadcasts, 0);
  await assert.rejects(run, /SP1 dependency security gate blocks/);
  assert.equal(broadcasts, 0);
});

test("an externally signed request is imported and broadcast without any local key", async () => {
  const inputPlan = plan();
  const action = nextFundingActivationAction(inputPlan, snapshot(inputPlan));
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address; action.signer = signer.address;
  const populator = {
    address: signer.address,
    populateTransaction: async (request) => ({ ...request, nonce: 7, gasLimit: 100_000n, gasPrice: 1n }),
  };
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-external-")));
  chmodSync(root, 0o700);
  const journalPath = join(root, "journal.json");
  const request = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: populator, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(7),
  });
  const rawTx = await signer.signTransaction(ethers.Transaction.from(request.unsignedTransaction));
  const transaction = ethers.Transaction.from(rawTx);
  const signedRecord = {
    schema_version: "p42-signed-transaction/v1", label: request.label,
    signer: signer.address.toLowerCase(), hash: ethers.keccak256(rawTx), raw_tx: rawTx,
    chain_id: inputPlan.chainId, nonce: transaction.nonce, to: transaction.to.toLowerCase(),
    value: transaction.value.toString(), data_hash: ethers.keccak256(transaction.data),
    signed_at_utc: new Date().toISOString(),
    activation_request_generation: request.requestGeneration,
    activation_request_expires_at: request.requestExpiresAt,
    activation_request_unsigned_hash: request.unsignedHash,
  };
  let observedProvider;
  const provider = {};
  const result = await signAndBroadcastActivationAction({
    plan: inputPlan, action, provider, signedRecord, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(7),
    transactionReconciler: async (candidate, record) => {
      observedProvider = candidate;
      assert.equal(record.hash, signedRecord.hash);
      return { status: "pending", transaction: {} };
    },
  });
  assert.equal(observedProvider, provider);
  assert.equal(result.status, "broadcast");
});

test("stale unsigned requests regenerate at the dual-RPC current nonce", async () => {
  const inputPlan = plan();
  const action = nextFundingActivationAction(inputPlan, snapshot(inputPlan));
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address; action.signer = signer.address;
  const populator = {
    address: signer.address,
    populateTransaction: async (request) => ({ ...request, gasLimit: 100_000n, gasPrice: 1n }),
  };
  let currentNonce = 4;
  const evidence = (candidate) => nonceEvidence(currentNonce)(candidate);
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-stale-request-")));
  chmodSync(root, 0o700);
  const journalPath = join(root, "journal.json");
  const first = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: populator, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: evidence,
  });
  currentNonce = 5;
  const second = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: populator, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_010n,
    nonceEvidence: evidence,
  });
  const journal = JSON.parse(readFileSync(journalPath, "utf8"));
  assert.equal(first.nonce, 4);
  assert.equal(second.nonce, 5);
  assert.equal(second.requestGeneration, first.requestGeneration + 1);
  assert.notEqual(second.unsignedHash, first.unsignedHash);
  assert.deepEqual(journal.transactions, {});
  assert.equal(journal.generation, second.requestGeneration);
});

test("restart migrates a signed v2 journal request from signing-request v1 without changing bytes", async () => {
  const inputPlan = plan();
  const action = nextFundingActivationAction(inputPlan, snapshot(inputPlan));
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address; action.signer = signer.address;
  const populator = {
    address: signer.address,
    populateTransaction: async (request) => ({ ...request, gasLimit: 100_000n, gasPrice: 1n }),
  };
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-v2-request-migrate-")));
  chmodSync(root, 0o700);
  const journalPath = join(root, "journal.json");
  const request = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: populator, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(6),
  });
  const rawTx = await signer.signTransaction(ethers.Transaction.from(request.unsignedTransaction));
  const transaction = ethers.Transaction.from(rawTx);
  const record = {
    schema_version: "p42-signed-transaction/v1", label: request.label,
    signer: signer.address.toLowerCase(), hash: ethers.keccak256(rawTx), raw_tx: rawTx,
    chain_id: inputPlan.chainId, nonce: transaction.nonce, to: transaction.to.toLowerCase(),
    value: transaction.value.toString(), data_hash: ethers.keccak256(transaction.data),
    signed_at_utc: new Date().toISOString(), status: "signed",
  };
  const legacyRequest = { ...request, schema: "p42-funding-activation-signing-request/v1" };
  for (const key of ["generatedAt", "requestExpiresAt", "requestGeneration", "nonceEvidence"]) {
    delete legacyRequest[key];
  }
  const journal = JSON.parse(readFileSync(journalPath, "utf8"));
  journal.signingRequests[request.label] = legacyRequest;
  journal.transactions[request.label] = record;
  writeFileSync(journalPath, `${JSON.stringify(journal, null, 2)}\n`, { mode: 0o600 });

  const migrated = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: null, journalRoot: root, journalPath,
    revalidate: async () => { throw new Error("signed restart must not repopulate"); },
    currentTimestamp: async () => 1_900_000_010n,
    nonceEvidence: async () => { throw new Error("signed restart must not refresh nonce"); },
  });
  assert.equal(migrated.schema, "p42-funding-activation-signing-request/v2");
  assert.equal(migrated.unsignedHash, request.unsignedHash);
  assert.equal(migrated.requestGeneration, 2);
  assert.equal(migrated.migratedSignedRequest, true);
});

test("a stale external signature cannot consume or replace unrelated signer nonce activity", async () => {
  const inputPlan = plan();
  const action = nextFundingActivationAction(inputPlan, snapshot(inputPlan));
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address; action.signer = signer.address;
  const populator = {
    address: signer.address,
    populateTransaction: async (request) => ({ ...request, gasLimit: 100_000n, gasPrice: 1n }),
  };
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-stale-import-")));
  chmodSync(root, 0o700);
  const journalPath = join(root, "journal.json");
  const request = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: populator, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(7),
  });
  const rawTx = await signer.signTransaction(ethers.Transaction.from(request.unsignedTransaction));
  const transaction = ethers.Transaction.from(rawTx);
  const signedRecord = {
    schema_version: "p42-signed-transaction/v1", label: request.label,
    signer: signer.address.toLowerCase(), hash: ethers.keccak256(rawTx), raw_tx: rawTx,
    chain_id: inputPlan.chainId, nonce: transaction.nonce, to: transaction.to.toLowerCase(),
    value: transaction.value.toString(), data_hash: ethers.keccak256(transaction.data),
    signed_at_utc: new Date().toISOString(),
    activation_request_generation: request.requestGeneration,
    activation_request_expires_at: request.requestExpiresAt,
    activation_request_unsigned_hash: request.unsignedHash,
  };
  await assert.rejects(() => signAndBroadcastActivationAction({
    plan: inputPlan, action, provider: {}, signedRecord, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_010n,
    nonceEvidence: nonceEvidence(8),
  }), /nonce is stale/);
  assert.deepEqual(JSON.parse(readFileSync(journalPath, "utf8")).transactions, {});

  const regenerated = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: populator, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_010n,
    nonceEvidence: nonceEvidence(8),
  });
  assert.equal(regenerated.nonce, 8);
  assert.equal(regenerated.requestGeneration, request.requestGeneration + 1);
});

test("external signatures bind the current semantic journal generation", async () => {
  const inputPlan = plan();
  const action = nextFundingActivationAction(inputPlan, snapshot(inputPlan));
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address; action.signer = signer.address;
  const populator = {
    address: signer.address,
    populateTransaction: async (request) => ({ ...request, gasLimit: 100_000n, gasPrice: 1n }),
  };
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-generation-import-")));
  chmodSync(root, 0o700);
  const journalPath = join(root, "journal.json");
  const request = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: populator, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(3),
  });
  const state = snapshot(inputPlan);
  state.blockNumber = 51; state.blockHash = `0x${"6".repeat(64)}`;
  state.timelockOperations[inputPlan.operations[10].operationId.toLowerCase()].confirmedBy = [inputPlan.governanceSigners[0]];
  reconcileFundingActivationConfirmations({ plan: inputPlan, snapshot: state, journalRoot: root, journalPath });
  const rawTx = await signer.signTransaction(ethers.Transaction.from(request.unsignedTransaction));
  const transaction = ethers.Transaction.from(rawTx);
  const signedRecord = {
    schema_version: "p42-signed-transaction/v1", label: request.label,
    signer: signer.address.toLowerCase(), hash: ethers.keccak256(rawTx), raw_tx: rawTx,
    chain_id: inputPlan.chainId, nonce: transaction.nonce, to: transaction.to.toLowerCase(),
    value: transaction.value.toString(), data_hash: ethers.keccak256(transaction.data),
    signed_at_utc: new Date().toISOString(),
    activation_request_generation: request.requestGeneration,
    activation_request_expires_at: request.requestExpiresAt,
    activation_request_unsigned_hash: request.unsignedHash,
  };
  await assert.rejects(() => signAndBroadcastActivationAction({
    plan: inputPlan, action, provider: {}, signedRecord, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_010n,
    nonceEvidence: nonceEvidence(3),
  }), /current journal generation/);
});

test("later finalized anchors with unchanged confirmations preserve an external signing request", async () => {
  const inputPlan = plan();
  const action = nextFundingActivationAction(inputPlan, snapshot(inputPlan));
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address; action.signer = signer.address;
  const populator = {
    address: signer.address,
    populateTransaction: async (request) => ({ ...request, gasLimit: 100_000n, gasPrice: 1n }),
  };
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-anchor-import-")));
  chmodSync(root, 0o700);
  const journalPath = join(root, "journal.json");
  const state = snapshot(inputPlan);
  const operationId = inputPlan.operations[10].operationId.toLowerCase();
  state.timelockOperations[operationId].confirmedBy = [inputPlan.governanceSigners[0]];
  state.blockNumber = 50; state.blockHash = `0x${"5".repeat(64)}`;
  reconcileFundingActivationConfirmations({ plan: inputPlan, snapshot: state, journalRoot: root, journalPath });
  const request = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: populator, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(3),
  });
  const generation = JSON.parse(readFileSync(journalPath, "utf8")).generation;

  state.blockNumber = 51; state.blockHash = `0x${"6".repeat(64)}`;
  reconcileFundingActivationConfirmations({ plan: inputPlan, snapshot: state, journalRoot: root, journalPath });
  const afterProgression = JSON.parse(readFileSync(journalPath, "utf8"));
  assert.equal(afterProgression.finalizedState.blockNumber, 51);
  assert.equal(afterProgression.generation, generation);

  const rawTx = await signer.signTransaction(ethers.Transaction.from(request.unsignedTransaction));
  const transaction = ethers.Transaction.from(rawTx);
  const signedRecord = {
    schema_version: "p42-signed-transaction/v1", label: request.label,
    signer: signer.address.toLowerCase(), hash: ethers.keccak256(rawTx), raw_tx: rawTx,
    chain_id: inputPlan.chainId, nonce: transaction.nonce, to: transaction.to.toLowerCase(),
    value: transaction.value.toString(), data_hash: ethers.keccak256(transaction.data),
    signed_at_utc: new Date().toISOString(),
    activation_request_generation: request.requestGeneration,
    activation_request_expires_at: request.requestExpiresAt,
    activation_request_unsigned_hash: request.unsignedHash,
  };
  const result = await signAndBroadcastActivationAction({
    plan: inputPlan, action, provider: {}, signedRecord, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_010n,
    nonceEvidence: nonceEvidence(3),
    transactionReconciler: async () => ({ status: "pending", transaction: {} }),
  });
  assert.equal(result.status, "broadcast");
});

test("signed journal records fence their request against nonce regeneration", async () => {
  const inputPlan = plan();
  const action = nextFundingActivationAction(inputPlan, snapshot(inputPlan));
  const signer = ethers.Wallet.createRandom();
  inputPlan.treasury = signer.address; action.signer = signer.address;
  const wallet = {
    address: signer.address, provider: {},
    populateTransaction: async (request) => ({ ...request, gasLimit: 100_000n, gasPrice: 1n }),
    signTransaction: (request) => signer.signTransaction(request),
  };
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-signed-fence-")));
  chmodSync(root, 0o700);
  const journalPath = join(root, "journal.json");
  const request = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: wallet, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(2),
  });
  await signAndBroadcastActivationAction({
    plan: inputPlan, action, wallet, provider: {}, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_000n,
    nonceEvidence: nonceEvidence(2),
    transactionReconciler: async () => ({ status: "pending", transaction: {} }),
  });
  const before = readFileSync(journalPath);
  const retained = await prepareActivationSigningRequest({
    plan: inputPlan, action, signer: wallet, journalRoot: root, journalPath,
    revalidate: async () => inputPlan, currentTimestamp: async () => 1_900_000_100n,
    nonceEvidence: nonceEvidence(3),
  });
  assert.equal(retained.unsignedHash, request.unsignedHash);
  assert.deepEqual(readFileSync(journalPath), before);
});

test("one governance signer waits after its confirmation instead of requiring quorum keys", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  for (const board of state.boards) {
    board.authorizedFundingDigest = chainDigest;
    board.fundingAuthorizationExpiresAt = BigInt(inputPlan.authorizationExpiresAt);
    board.fundingAuthorizationNonce = 1n;
    board.fundingAuthorizationVerified = true;
  }
  const operation = inputPlan.operations[10];
  const operationState = state.timelockOperations[operation.operationId.toLowerCase()];
  operationState.state = 1;
  operationState.confirmedBy = [inputPlan.governanceSigners[0]];
  const action = nextFundingActivationAction(inputPlan, state, {
    availableGovernanceSigners: [inputPlan.governanceSigners[0]],
  });
  assert.equal(action.kind, "wait-signers");
});

test("finalized governance confirmations persist monotonically in the shared journal", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  state.blockNumber = 50; state.blockHash = `0x${"5".repeat(64)}`;
  const operation = inputPlan.operations[10];
  state.timelockOperations[operation.operationId.toLowerCase()].confirmedBy = [inputPlan.governanceSigners[0]];
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-confirmations-")));
  chmodSync(root, 0o700);
  const journalPath = join(root, "journal.json");
  reconcileFundingActivationConfirmations({ plan: inputPlan, snapshot: state, journalRoot: root, journalPath });
  const journal = JSON.parse(readFileSync(journalPath, "utf8"));
  assert.deepEqual(journal.finalizedState.confirmations[operation.operationId.toLowerCase()], [inputPlan.governanceSigners[0]]);
  state.blockNumber = 49; state.blockHash = `0x${"4".repeat(64)}`;
  const retained = reconcileFundingActivationConfirmations({ plan: inputPlan, snapshot: state, journalRoot: root, journalPath });
  assert.equal(retained.blockNumber, 50);
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
    authorizationNonce: selector("fundingAuthorizationNonce()"),
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
      if (id === selectors.authorizationNonce) return coder.encode(["uint256"], [0]);
      if (id === selectors.armed || id === selectors.accepting || id === selectors.confirmed) return coder.encode(["bool"], [false]);
      if (id === selectors.state) return coder.encode(["uint8"], [0]);
      if (id === selectors.ops) return coder.encode(["uint64", "uint64", "uint32", "uint32", "uint8", "bool", "bytes32"], [0, 0, 0, 0, 0, false, ZERO_HASH]);
      throw new Error(`unexpected selector ${id}`);
    },
  });
  const snapshot = await collectFundingActivationSnapshot(inputPlan, provider(), provider(), observedRpcAuthority());
  assert.equal(snapshot.blockNumber, 50);
  assert.equal(snapshot.boards.length, 10);
  assert.equal(snapshot.boards[0].fundingAuthorizationNonce, 0n);
  assert.equal(snapshot.boards[0].fundingAuthorizationVerified, false);
  await assert.rejects(() => collectFundingActivationSnapshot(inputPlan, provider(), provider(1_900_000_001), observedRpcAuthority()), /disagree/);
});

test("activation checkpoint evidence validates pure exact observations without a provider seam", () => {
  const inputPlan = plan();
  const anchor = { number: 50, hash: `0x${"5".repeat(64)}`, timestamp: 1_900_000_000 };
  const completionAnchor = {
    completionDigest: `sha256:${"c".repeat(64)}`,
    blockNumber: 40,
    blockHash: `0x${"4".repeat(64)}`,
    blockTimestamp: 1_899_999_000,
  };
  const observation = (role = "primary") => ({
    rpcProfile: { ...observedRpcAuthority()[role] },
    chainId: inputPlan.chainId,
    finalizedBlockNumber: 50,
    blockNumber: 50,
    blockHash: anchor.hash,
    blockTimestamp: anchor.timestamp,
    completionAnchor: { ...completionAnchor },
    operations: inputPlan.operations.slice(10).map((operation) => ({
      sequence: operation.sequence,
      label: operation.label,
      problemId: String(operation.problemId),
      operationId: operation.operationId,
      state: 2,
      storageState: 2,
    })),
  });
  const primary = observation();
  const secondary = observation("secondary");
  const evidence = validateFundingActivationOperationObservations(
    inputPlan, primary, secondary, anchor, completionAnchor,
  );
  assert.equal(evidence.finalizedBlockNumber, 50);
  assert.equal(evidence.operations.length, 20);
  assert.deepEqual(evidence.operations.map(({ operationId }) => operationId), inputPlan.operations.slice(10).map(({ operationId }) => operationId.toLowerCase()));
  assert.ok(evidence.operations.every(({ state }) => state === 2));
  const none = observation(); none.operations[0].state = 0; none.operations[0].storageState = 0;
  assert.throws(() => validateFundingActivationOperationObservations(inputPlan, none, secondary, anchor, completionAnchor), /not executed/);
  const splitState = observation(); splitState.operations[0].storageState = 1;
  assert.throws(() => validateFundingActivationOperationObservations(inputPlan, splitState, secondary, anchor, completionAnchor), /canonical operation set/);
  const wrongHash = observation("secondary"); wrongHash.blockHash = `0x${"6".repeat(64)}`;
  assert.throws(() => validateFundingActivationOperationObservations(inputPlan, primary, wrongHash, anchor, completionAnchor), /wrong anchor/);
  const unfinalized = observation("secondary"); unfinalized.finalizedBlockNumber = 49;
  assert.throws(() => validateFundingActivationOperationObservations(inputPlan, primary, unfinalized, anchor, completionAnchor), /wrong anchor/);
  const reorgedCompletion = observation("secondary");
  reorgedCompletion.completionAnchor.blockHash = `0x${"9".repeat(64)}`;
  assert.throws(
    () => validateFundingActivationOperationObservations(
      inputPlan, primary, reorgedCompletion, anchor, completionAnchor,
    ),
    /wrong anchor/,
  );
  const substitutedProfile = observation("secondary");
  substitutedProfile.rpcProfile.endpointProfileDigest = `sha256:${"0".repeat(64)}`;
  assert.throws(
    () => validateFundingActivationOperationObservations(inputPlan, primary, substitutedProfile, anchor, completionAnchor),
    /RPC authority does not match the plan/,
  );
  assert.equal("fundingActivationOperationEvidenceTestOnly" in activationExecutorModule, false);
});

test("executor rejects stale bundle nonces and requires post-relay verified nonce semantics", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  state.boards[0].fundingAuthorizationNonce = 1n;
  assert.throws(() => nextFundingActivationAction(inputPlan, state), /nonce does not match signature bundle/);

  state.boards[0].authorizedFundingDigest = chainDigest;
  state.boards[0].fundingAuthorizationExpiresAt = BigInt(inputPlan.authorizationExpiresAt);
  state.boards[0].fundingAuthorizationVerified = false;
  assert.throws(() => nextFundingActivationAction(inputPlan, state), /conflicting funding authorization/);
});

test("dual-RPC nonce evidence binds finalized and pending current nonces", async () => {
  const signer = address(77);
  const provider = (pendingNonce = 9) => ({
    getBlock: async (tag) => {
      const number = tag === "finalized" ? 40 : tag === "latest" ? 50 : Number(tag);
      return {
        number,
        hash: `0x${(number === 40 ? "4" : "5").repeat(64)}`,
        timestamp: number === 40 ? 1_899_999_000 : 1_900_000_000,
      };
    },
    getTransactionCount: async (_address, tag) => tag === "pending" ? pendingNonce : 7,
  });
  const evidence = await collectActivationNonceEvidence(provider(), provider(), signer);
  assert.equal(evidence.finalizedNonce, 7);
  assert.equal(evidence.currentNonce, 9);
  await assert.rejects(
    () => collectActivationNonceEvidence(provider(9), provider(10), signer),
    /disagree on the signer nonce/,
  );
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
    nonceEvidence: nonceEvidence(0),
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
    nonceEvidence: nonceEvidence(0),
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
    populateTransaction: async (request) => ({ ...request, nonce: 0, gasLimit: 100_000n, gasPrice: 1n }),
    signTransaction: async (request) => { signed = true; return signer.signTransaction(request); },
  };
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p42-activation-populate-")));
  chmodSync(root, 0o700);
  await assert.rejects(() => prepareActivationSigningRequest({
    plan: inputPlan, action, wallet, journalRoot: root, journalPath: join(root, "journal.json"),
    signer: wallet,
    revalidate: async () => inputPlan,
    currentTimestamp: async () => (++timeReads < 3
      ? BigInt(inputPlan.authorizationExpiresAt) - 1n
      : BigInt(inputPlan.authorizationExpiresAt) + 1n),
    nonceEvidence: nonceEvidence(0),
  }), /expired during transaction population/);
  assert.equal(signed, false);
});

test("completion artifact binds only the exact finalized all-open state", () => {
  const inputPlan = plan();
  const state = snapshot(inputPlan);
  for (const board of state.boards) {
    board.authorizedFundingDigest = chainDigest;
    board.fundingAuthorizationExpiresAt = BigInt(inputPlan.authorizationExpiresAt);
    board.fundingAuthorizationNonce = 1n;
    board.fundingAuthorizationVerified = true;
    board.fundingArmed = true;
    board.fundingAuthorizationDigest = chainDigest;
    board.acceptingFunds = true;
  }
  for (const operation of inputPlan.operations.slice(10)) {
    state.timelockOperations[operation.operationId.toLowerCase()].state = 2;
  }
  state.blockNumber = 42;
  state.blockHash = `0x${"4".repeat(64)}`;
  const completion = buildFundingActivationCompletion(inputPlan, state);
  assert.equal(completion.status, "complete");
  assert.equal(completion.boards.length, 10);
  assert.deepEqual(completion.boards[0].armOperation, {
    operationId: inputPlan.operations[10].operationId,
    state: 2,
  });
  assert.deepEqual(completion.boards[0].openOperation, {
    operationId: inputPlan.operations[20].operationId,
    state: 2,
  });
  assert.match(completion.completionDigest, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(fundingActivationCompletionAnchor(inputPlan, completion), {
    completionDigest: completion.completionDigest,
    blockNumber: completion.finalizedBlockNumber,
    blockHash: completion.finalizedBlockHash.toLowerCase(),
    blockTimestamp: completion.finalizedBlockTimestamp,
  });
  assert.throws(
    () => fundingActivationCompletionAnchor(inputPlan, {
      ...completion, finalizedBlockHash: `0x${"9".repeat(64)}`,
    }),
    /does not match/,
  );
  const stripped = { ...completion };
  delete stripped.rpcAuthority;
  const { completionDigest: _ignored, ...strippedBody } = stripped;
  stripped.completionDigest = `sha256:${createHash("sha256").update(canonicalJson(strippedBody)).digest("hex")}`;
  assert.throws(() => fundingActivationCompletionAnchor(inputPlan, stripped), /does not match/);
  const wrongChainEvidence = structuredClone(completion);
  wrongChainEvidence.rpcAuthority.primary.observedRawChainId = "0x1";
  delete wrongChainEvidence.completionDigest;
  wrongChainEvidence.completionDigest = `sha256:${createHash("sha256").update(canonicalJson(wrongChainEvidence)).digest("hex")}`;
  assert.throws(() => fundingActivationCompletionAnchor(inputPlan, wrongChainEvidence), /raw chain IDs/);
  state.boards[0].acceptingFunds = false;
  assert.throws(
    () => buildFundingActivationCompletion(inputPlan, state),
    /exact pool-open operation executed without matching pool state/,
  );
});
