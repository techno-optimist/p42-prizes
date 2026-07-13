import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

const { ethers } = await network.create();

async function fixture() {
  const programVKey = ethers.id("p42-sp1-a11-vkey");
  const journalDigest = ethers.id("p42-objective-journal");
  const proof = ethers.hexlify(ethers.toUtf8Bytes("sp1-groth16-proof"));
  const Verifier = await ethers.getContractFactory("MockSP1Verifier");
  const verifier = await Verifier.deploy(programVKey, journalDigest, ethers.keccak256(proof));
  const verifierAddress = await verifier.getAddress();
  const verifierCodehash = ethers.keccak256(await ethers.provider.getCode(verifierAddress));
  const Gateway = await ethers.getContractFactory("MockP42SP1VerifierGateway");
  const gateway = await Gateway.deploy(verifierAddress, verifierCodehash);
  return { Gateway, gateway, verifier, verifierAddress, verifierCodehash, programVKey, journalDigest, proof };
}

describe("P42SP1VerifierGateway", () => {
  it("pins the exact verifier runtime and forwards the exact public values", async () => {
    const f = await fixture();
    assert.equal(await f.gateway.sp1Verifier(), f.verifierAddress);
    assert.equal(await f.gateway.sp1VerifierCodehash(), f.verifierCodehash);
    assert.equal(await f.gateway.objectiveProofsActive(), true);
    assert.equal(await f.gateway.verify(f.programVKey, f.journalDigest, f.proof), true);
  });

  it("fails closed for zero, code-free, zero-codehash, and mismatched verifier bindings", async () => {
    const f = await fixture();
    const [account] = await ethers.getSigners();
    for (const gateway of [
      await f.Gateway.deploy(ethers.ZeroAddress, f.verifierCodehash),
      await f.Gateway.deploy(await account.getAddress(), f.verifierCodehash),
      await f.Gateway.deploy(f.verifierAddress, ethers.ZeroHash),
      await f.Gateway.deploy(f.verifierAddress, ethers.id("wrong-runtime")),
    ]) await assert.rejects(gateway.verify(f.programVKey, f.journalDigest, f.proof), /BadSP1VerifierRuntime/);
  });

  it("bubbles invalid proof, vkey, and journal failures instead of returning false", async () => {
    const f = await fixture();
    await assert.rejects(f.gateway.verify(ethers.id("wrong-vkey"), f.journalDigest, f.proof), /InvalidSP1Proof/);
    await assert.rejects(f.gateway.verify(f.programVKey, ethers.id("wrong-journal"), f.proof), /InvalidSP1Proof/);
    await assert.rejects(f.gateway.verify(f.programVKey, f.journalDigest, "0x1234"), /InvalidSP1Proof/);
  });

  it("fails closed if the pinned verifier runtime changes", async () => {
    const f = await fixture();
    await ethers.provider.send("hardhat_setCode", [f.verifierAddress, "0x60006000fd"]);
    await assert.rejects(f.gateway.verify(f.programVKey, f.journalDigest, f.proof), /BadSP1VerifierRuntime/);
  });

  it("pins the Base V6.1 verifier but keeps production proofs fail-closed until A11 is released", async () => {
    const Gateway = await ethers.getContractFactory("P42SP1VerifierGateway");
    const gateway = await Gateway.deploy();
    assert.equal(await gateway.sp1Verifier(), "0xb69f2584CBcFf99a58C4e7002E8b89Af54a6f4e2");
    assert.equal(
      await gateway.sp1VerifierCodehash(),
      "0xcceb864cd8a5a36b2073a8f2b32a773835cd2dd2c78a56f8e6fdb942feff04dd",
    );
    assert.equal(await gateway.objectiveProofsActive(), false);
    await assert.rejects(
      gateway.verify(ethers.id("vkey"), ethers.id("journal"), "0x"),
      /ObjectiveProofCapabilityInactive/,
    );
  });
});
