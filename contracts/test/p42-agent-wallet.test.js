import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();

async function expectCustomError(action, contract, errorName) {
  try {
    await action;
  } catch (error) {
    const data = findErrorData(error);
    if (data !== undefined) {
      const parsed = contract.interface.parseError(data);
      assert.equal(parsed?.name, errorName);
      return;
    }
    assert.match(String(error), new RegExp(errorName));
    return;
  }
  throw new Error(`expected ${errorName} revert`);
}

function findErrorData(value) {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "string") return /^0x[0-9a-fA-F]+$/.test(value) ? value : undefined;
  if (typeof value !== "object") return undefined;
  if (typeof value.data === "string" && /^0x[0-9a-fA-F]+$/.test(value.data)) return value.data;
  if (typeof value.error?.data === "string") return value.error.data;
  if (typeof value.info?.error?.data === "string") return value.info.error.data;
  for (const nested of [value.cause, value.error, value.info?.error]) {
    const d = findErrorData(nested);
    if (d !== undefined) return d;
  }
  return undefined;
}

const PER_CALL = ethers.parseEther("0.001");
const TOTAL = ethers.parseEther("0.003");
const FUNDING = ethers.parseEther("0.005");
const FUNDING_CAP = ethers.parseEther("1");
const CLOSE_BY_TIMESTAMP = 4_102_444_800n;
const MIN_COMPETITION_SECONDS = 30n * 24n * 60n * 60n;

async function nextEarliestClose() {
  const latest = await ethers.provider.getBlock("latest");
  return BigInt(latest.timestamp) + MIN_COMPETITION_SECONDS + 1_000n;
}

async function fixture() {
  const [deployer, owner, session, outsider] = await ethers.getSigners();
  // A real P42 contract to act as an allowlist target (fund() is payable).
  const Pool = await ethers.getContractFactory("P42BountyPool");
  const pool = await Pool.deploy(deployer.address, FUNDING_CAP);
  await pool.waitForDeployment();
  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const ledger = await Ledger.deploy(
    await pool.getAddress(), deployer.address, deployer.address, 0,
    await nextEarliestClose(), CLOSE_BY_TIMESTAMP
  );
  await ledger.waitForDeployment();
  await pool.connect(deployer).setLedger(await ledger.getAddress());
  // fund() is gated on an armed submission manager (open-witness-phase rail);
  // these tests exercise the wallet, so wire the pre-armed mock.
  const Mock = await ethers.getContractFactory("MockFundingArmed");
  const mock = await Mock.deploy(true);
  await mock.waitForDeployment();
  await ledger.connect(deployer).setCreditRecorder(await mock.getAddress());
  await pool.connect(deployer).setSubmissionManager(await mock.getAddress());
  const Registry = await ethers.getContractFactory("P42ProblemRegistry");
  const registry = await Registry.deploy(deployer.address);
  await registry.waitForDeployment();
  await registry.register({
    specHash: ethers.id("wallet-spec"),
    verifierSourceHash: ethers.id("wallet-source"),
    verifierImageHash: ethers.id("wallet-image"),
    admissionMatrixHash: ethers.id("wallet-matrix"),
    metadataURI: "ipfs://wallet-fixture",
    pool: await pool.getAddress(),
    ledger: await ledger.getAddress(),
    submissionManager: await mock.getAddress(),
    challengeManager: deployer.address,
    challengeWindowSeconds: 90n,
    minImprovementAtoms: 1n,
  });
  await registry.freeze(1);
  await pool.connect(deployer).setRegistry(await registry.getAddress(), 1);
  const Vault = await ethers.getContractFactory("P42RolloverVault");
  const vault = await Vault.deploy(await registry.getAddress(), deployer.address);
  await vault.waitForDeployment();
  await ledger.connect(deployer).setRolloverDestination(await vault.getAddress());
  await pool.connect(deployer).setAcceptingFunds(true);
  const Wallet = await ethers.getContractFactory("P42AgentWallet");
  const wallet = await Wallet.connect(owner).deploy(owner.address, session.address, PER_CALL, TOTAL, { value: FUNDING });
  await wallet.waitForDeployment();
  const fundSel = pool.interface.getFunction("fund").selector;
  const claimSel = pool.interface.getFunction("claim").selector;
  await wallet.connect(owner).setAllowed(await pool.getAddress(), fundSel, true);
  const fundData = pool.interface.encodeFunctionData("fund", []);
  const claimData = pool.interface.encodeFunctionData("claim", []);
  return { deployer, owner, session, outsider, pool, wallet, fundData, claimData };
}

describe("P42AgentWallet — scoped session-key safety", () => {
  it("lets the session key forward an allowlisted call within caps", async () => {
    const { session, pool, wallet, fundData } = await fixture();
    await wallet.connect(session).execute(await pool.getAddress(), PER_CALL, fundData);
    assert.equal(await pool.totalFunded(), PER_CALL);
    assert.equal(await wallet.spentWei(), PER_CALL);
  });

  it("rejects a non-allowlisted (target, selector) — funds cannot be redirected", async () => {
    const { session, pool, wallet, claimData } = await fixture();
    // claim() is not allowlisted
    await expectCustomError(
      wallet.connect(session).execute(await pool.getAddress(), 0n, claimData),
      wallet, "CallNotAllowed");
    // arbitrary address with empty calldata is not allowlisted either
    await expectCustomError(
      wallet.connect(session).execute(ethers.Wallet.createRandom().address, PER_CALL, "0x"),
      wallet, "CallNotAllowed");
  });

  it("limits a selector-zero allowance to bare empty calldata", async () => {
    const { owner, session, outsider, wallet } = await fixture();
    // A raw transfer can be intentional, but arbitrary fallback bytes must
    // never inherit the selector-zero compatibility allowance.
    await wallet.connect(owner).setAllowed(outsider.address, "0x00000000", true);
    await wallet.connect(session).execute(outsider.address, 0n, "0x");

    for (const fallbackData of ["0x01", "0x0102", "0x010203", "0x00000000"]) {
      await expectCustomError(
        wallet.connect(session).execute(outsider.address, 0n, fallbackData),
        wallet, "ExactCalldataPolicyRequired");
    }
  });

  it("enforces the per-call value cap", async () => {
    const { session, pool, wallet, fundData } = await fixture();
    await expectCustomError(
      wallet.connect(session).execute(await pool.getAddress(), PER_CALL + 1n, fundData),
      wallet, "ValueCapExceeded");
  });

  it("enforces the cumulative spend cap", async () => {
    const { session, pool, wallet, fundData } = await fixture();
    const addr = await pool.getAddress();
    await wallet.connect(session).execute(addr, PER_CALL, fundData); // 0.001
    await wallet.connect(session).execute(addr, PER_CALL, fundData); // 0.002
    await wallet.connect(session).execute(addr, PER_CALL, fundData); // 0.003 == TOTAL
    await expectCustomError(
      wallet.connect(session).execute(addr, PER_CALL, fundData), // would be 0.004 > TOTAL
      wallet, "SpendCapExceeded");
  });

  it("only the session key can execute", async () => {
    const { owner, outsider, pool, wallet, fundData } = await fixture();
    await expectCustomError(
      wallet.connect(outsider).execute(await pool.getAddress(), 0n, fundData), wallet, "NotSession");
    await expectCustomError(
      wallet.connect(owner).execute(await pool.getAddress(), 0n, fundData), wallet, "NotSession");
  });

  it("owner can revoke the session key (kill-switch), and re-key", async () => {
    const { owner, session, outsider, pool, wallet, fundData } = await fixture();
    await wallet.connect(owner).revoke();
    await expectCustomError(
      wallet.connect(session).execute(await pool.getAddress(), PER_CALL, fundData), wallet, "KeyRevoked");
    // owner rotates to a new session key, which resets revoked
    await wallet.connect(owner).setSessionKey(outsider.address);
    await wallet.connect(outsider).execute(await pool.getAddress(), PER_CALL, fundData);
    assert.equal(await pool.totalFunded(), PER_CALL);
  });

  it("rotating the session key resets the spend meter so the fresh key gets the full cap (F18)", async () => {
    const { owner, session, outsider, pool, wallet, fundData } = await fixture();
    const addr = await pool.getAddress();
    // Old key exhausts the cumulative cap.
    await wallet.connect(session).execute(addr, PER_CALL, fundData);
    await wallet.connect(session).execute(addr, PER_CALL, fundData);
    await wallet.connect(session).execute(addr, PER_CALL, fundData); // spentWei == TOTAL
    await expectCustomError(
      wallet.connect(session).execute(addr, PER_CALL, fundData), wallet, "SpendCapExceeded");

    // Owner rotates to a fresh key (no setCaps needed) and tops up the balance.
    await wallet.connect(owner).setSessionKey(outsider.address);
    assert.equal(await wallet.spentWei(), 0n);
    await owner.sendTransaction({ to: await wallet.getAddress(), value: TOTAL });

    // The new key can immediately spend value, all the way up to the cap...
    await wallet.connect(outsider).execute(addr, PER_CALL, fundData);
    await wallet.connect(outsider).execute(addr, PER_CALL, fundData);
    await wallet.connect(outsider).execute(addr, PER_CALL, fundData);
    assert.equal(await wallet.spentWei(), TOTAL);
    // ...but no further: the per-session cap still binds.
    await expectCustomError(
      wallet.connect(outsider).execute(addr, PER_CALL, fundData), wallet, "SpendCapExceeded");
  });

  it("gates owner-only controls and lets the owner withdraw (bounded max-loss recovery)", async () => {
    const { owner, session, outsider, pool, wallet } = await fixture();
    const sel = pool.interface.getFunction("fund").selector;
    const poolAddr = await pool.getAddress();
    const bad = [
      () => wallet.connect(outsider).revoke(),
      () => wallet.connect(session).setAllowed(poolAddr, sel, true),
      () => wallet.connect(outsider).setCaps(0n, 0n),
      () => wallet.connect(session).withdraw(session.address, 1n),
    ];
    for (const mk of bad) await expectCustomError(mk(), wallet, "NotOwner");
    const before = await ethers.provider.getBalance(owner.address);
    await (await wallet.connect(owner).withdraw(owner.address, FUNDING)).wait();
    assert.equal(await ethers.provider.getBalance(await wallet.getAddress()), 0n);
    assert.ok((await ethers.provider.getBalance(owner.address)) > before); // recovered ~FUNDING minus gas
  });
});
