import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();
const DELAY = 100n;

async function expectCustomError(action, contract, errorName) {
  try {
    await action;
  } catch (error) {
    const data = findErrorData(error);
    if (data !== undefined) {
      assert.equal(contract.interface.parseError(data)?.name, errorName);
      return;
    }
    assert.match(String(error), new RegExp(errorName));
    return;
  }
  throw new Error(`expected ${errorName} revert`);
}
function findErrorData(v) {
  if (v == null) return undefined;
  if (typeof v === "string") return /^0x[0-9a-fA-F]+$/.test(v) ? v : undefined;
  if (typeof v !== "object") return undefined;
  if (typeof v.data === "string" && /^0x[0-9a-fA-F]+$/.test(v.data)) return v.data;
  if (typeof v.error?.data === "string") return v.error.data;
  if (typeof v.info?.error?.data === "string") return v.info.error.data;
  for (const n of [v.cause, v.error, v.info?.error]) { const d = findErrorData(n); if (d !== undefined) return d; }
  return undefined;
}
async function advance(sec) {
  await ethers.provider.send("evm_increaseTime", [Number(sec)]);
  await ethers.provider.send("evm_mine", []);
}

async function fixture() {
  const [a, b, c, guardian, outsider] = await ethers.getSigners();
  const TL = await ethers.getContractFactory("P42MultisigTimelock");
  const tl = await TL.deploy([a.address, b.address, c.address], 2, DELAY, guardian.address);
  await tl.waitForDeployment();
  // A P42 contract owned BY the timelock — its onlyOwner setter is the demo target.
  const Ledger = await ethers.getContractFactory("P42PayoutLedger");
  const ledger = await Ledger.deploy(a.address, await tl.getAddress(), b.address, 0);
  await ledger.waitForDeployment();
  const salt = ethers.id("op-1");
  const pauseData = ledger.interface.encodeFunctionData("setPausedNewActions", [true]);
  return { a, b, c, guardian, outsider, tl, ledger, salt, pauseData, ledgerAddr: await ledger.getAddress() };
}

describe("P42MultisigTimelock — governance root of trust", () => {
  it("requires M-of-N confirmations AND the timelock before a privileged action executes", async () => {
    const { a, b, tl, ledger, salt, pauseData, ledgerAddr } = await fixture();
    await tl.connect(a).schedule(ledgerAddr, 0, pauseData, salt);
    // too early
    await expectCustomError(tl.execute(ledgerAddr, 0, pauseData, salt), tl, "NotReady");
    await advance(DELAY + 1n);
    // past timelock but only 1 of 2 confirmations
    await expectCustomError(tl.execute(ledgerAddr, 0, pauseData, salt), tl, "NotEnoughConfirmations");
    await tl.connect(b).confirm(await tl.opId(ledgerAddr, 0, pauseData, salt));
    // now both conditions met — anyone may execute
    await tl.execute(ledgerAddr, 0, pauseData, salt);
    assert.equal(await ledger.pausedNewActions(), true);
  });

  it("blocks non-signers from scheduling or confirming", async () => {
    const { a, outsider, tl, salt, pauseData, ledgerAddr } = await fixture();
    await expectCustomError(tl.connect(outsider).schedule(ledgerAddr, 0, pauseData, salt), tl, "NotSigner");
    await tl.connect(a).schedule(ledgerAddr, 0, pauseData, salt);
    const id = await tl.opId(ledgerAddr, 0, pauseData, salt);
    await expectCustomError(tl.connect(outsider).confirm(id), tl, "NotSigner");
  });

  it("lets the guardian veto a pending op (emergency brake), but no one else", async () => {
    const { a, b, outsider, guardian, tl, salt, pauseData, ledgerAddr } = await fixture();
    await tl.connect(a).schedule(ledgerAddr, 0, pauseData, salt);
    const id = await tl.opId(ledgerAddr, 0, pauseData, salt);
    await expectCustomError(tl.connect(outsider).cancel(id), tl, "NotGuardian");
    await expectCustomError(tl.connect(b).cancel(id), tl, "NotGuardian"); // signers can't cancel either
    await tl.connect(guardian).cancel(id);
    await advance(DELAY + 1n);
    await tl.connect(b).confirm(id).catch(() => {}); // confirming a cancelled op reverts; ignore
    await expectCustomError(tl.execute(ledgerAddr, 0, pauseData, salt), tl, "UnknownOp");
  });

  it("rejects double confirmation and re-scheduling the same op", async () => {
    const { a, tl, salt, pauseData, ledgerAddr } = await fixture();
    await tl.connect(a).schedule(ledgerAddr, 0, pauseData, salt);
    const id = await tl.opId(ledgerAddr, 0, pauseData, salt);
    await expectCustomError(tl.connect(a).confirm(id), tl, "AlreadyConfirmed"); // proposer already counted
    await expectCustomError(tl.connect(a).schedule(ledgerAddr, 0, pauseData, salt), tl, "OpExists");
  });

  it("rejects a bad threshold at construction", async () => {
    const [a, b] = await ethers.getSigners();
    const TL = await ethers.getContractFactory("P42MultisigTimelock");
    await expectCustomError(TL.deploy([a.address, b.address], 3, DELAY, a.address), TL, "BadThreshold");
    await expectCustomError(TL.deploy([a.address, b.address], 0, DELAY, a.address), TL, "BadThreshold");
  });
});
