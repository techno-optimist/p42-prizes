import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { network } from "hardhat";

const { ethers } = await network.create();
const here = dirname(fileURLToPath(import.meta.url));
const vector = JSON.parse(
  readFileSync(join(here, "fixtures", "sp1-v6.1-base-vector.json"), "utf8"),
);

const EXPECTED_SCOPE = "direct-sp1-verifier-conformance-not-p42-32-byte-guest-proof";
const EXPECTED_PROVENANCE = {
  chainId: 8453,
  network: "Base mainnet",
  transactionHash: "0x9910aa438b4996a35c7a53e4978924b394a968ce38b314a3f46cabcbcfefcf65",
  transactionStatus: "0x1",
  transactionIndex: "0x19",
  blockNumber: 48051861,
  blockTag: "0x2dd3695",
  blockHash: "0x4810ee0747139524bd98f983dc1c47edb197048ecdad7f4ed96520a12216d7ec",
  blockTimestamp: "2026-07-01T08:04:29.000000Z",
  transactionUrl:
    "https://base.blockscout.com/tx/0x9910aa438b4996a35c7a53e4978924b394a968ce38b314a3f46cabcbcfefcf65",
  traceUrl:
    "https://base.blockscout.com/api/v2/transactions/0x9910aa438b4996a35c7a53e4978924b394a968ce38b314a3f46cabcbcfefcf65/raw-trace",
  succinctRelease: "v6.1.0",
  succinctContractsCommit: "2ac5ecbbe473421a963d67e55f182e9a36576f7c",
  verifierSourceUrl:
    "https://github.com/succinctlabs/sp1-contracts/blob/v6.1.0/contracts/src/v6.1.0/SP1VerifierGroth16.sol",
  routingGateway: "0x397A5f7f3dBd538f23DE225B51f532c34448dA9B",
  verifierAddress: "0xb69f2584CBcFf99a58C4e7002E8b89Af54a6f4e2",
};
const EXPECTED_FROZEN = {
  runtimeLengthBytes: 6741,
  runtimeSha256: "0x7cde81642f1be1b21970c2cbfe19635d038cb0a33a124db71e3cee3acc96a781",
  runtimeCodehash: "0xcceb864cd8a5a36b2073a8f2b32a773835cd2dd2c78a56f8e6fdb942feff04dd",
  publicValuesLengthBytes: 288,
  publicValuesSha256: "0xa2db727a7cdbcfa5b7e1df3392ff188ac47c136d3e254846d0b5c7fbe7fd50cf",
  publicValuesKeccak256: "0x62f5e6f05e5779b952b0fb4072de2b710711f86d5568cf36c14dbf21b63f6bec",
  proofLengthBytes: 356,
  proofSha256: "0x2fd7bac6ebbb21aecb96ce21d4416f79ad82ec67e7213988992ab7544c15b74e",
  proofKeccak256: "0xfff24e4e43e6c25d25722434e971151ee2724dd70ea514404615672c024172e6",
  verifierCalldataKeccak256: "0x15530396ebdd4184eccfb8262701bb18fb271e747ba6bb5ff41c39cd28530883",
};
const EXPECTED_PROGRAM_VKEY =
  "0x007a730bfd5357cd975967e531267cc33b50623061627d41312ebbc7223ab586";
const VERIFIER_ABI = [
  "function verifyProof(bytes32 programVKey, bytes publicValues, bytes proofBytes) external view",
];

function mutateLastByte(value) {
  const bytes = ethers.getBytes(value);
  bytes[bytes.length - 1] ^= 1;
  return ethers.hexlify(bytes);
}

async function installFrozenVerifierRuntime() {
  await ethers.provider.send("hardhat_setCode", [
    EXPECTED_PROVENANCE.verifierAddress,
    vector.runtime,
  ]);
  return new ethers.Contract(
    EXPECTED_PROVENANCE.verifierAddress,
    VERIFIER_ABI,
    ethers.provider,
  );
}

describe("SP1 v6.1 direct verifier conformance", () => {
  it("pins the complete Base provenance, lengths, hashes, and direct-verifier scope", () => {
    assert.equal(vector.schemaVersion, "p42-sp1-v6.1-base-direct-conformance-v1");
    assert.equal(vector.evidenceScope, EXPECTED_SCOPE);
    assert.deepEqual(vector.provenance, EXPECTED_PROVENANCE);
    assert.deepEqual(vector.frozen, EXPECTED_FROZEN);
    assert.equal(vector.programVKey, EXPECTED_PROGRAM_VKEY);

    assert.equal(ethers.dataLength(vector.runtime), EXPECTED_FROZEN.runtimeLengthBytes);
    assert.equal(ethers.sha256(vector.runtime), EXPECTED_FROZEN.runtimeSha256);
    assert.equal(ethers.keccak256(vector.runtime), EXPECTED_FROZEN.runtimeCodehash);
    assert.equal(
      ethers.dataLength(vector.publicValues),
      EXPECTED_FROZEN.publicValuesLengthBytes,
    );
    assert.equal(ethers.sha256(vector.publicValues), EXPECTED_FROZEN.publicValuesSha256);
    assert.equal(
      ethers.keccak256(vector.publicValues),
      EXPECTED_FROZEN.publicValuesKeccak256,
    );
    assert.equal(ethers.dataLength(vector.proof), EXPECTED_FROZEN.proofLengthBytes);
    assert.equal(ethers.sha256(vector.proof), EXPECTED_FROZEN.proofSha256);
    assert.equal(ethers.keccak256(vector.proof), EXPECTED_FROZEN.proofKeccak256);
    assert.equal(vector.proof.slice(0, 10), "0x4388a21c");

    const verifier = new ethers.Interface(VERIFIER_ABI);
    const calldata = verifier.encodeFunctionData("verifyProof", [
      vector.programVKey,
      vector.publicValues,
      vector.proof,
    ]);
    assert.equal(
      ethers.keccak256(calldata),
      EXPECTED_FROZEN.verifierCalldataKeccak256,
    );

    // This direct-verifier evidence cannot activate P42's adapter: its journal is
    // 288 bytes, while the P42 guest contract requires exactly one 32-byte digest.
    assert.notEqual(EXPECTED_FROZEN.publicValuesLengthBytes, 32);
  });

  it("accepts the genuine vector against the exact deployed verifier runtime", async () => {
    const verifier = await installFrozenVerifierRuntime();
    assert.equal(
      ethers.keccak256(
        await ethers.provider.getCode(EXPECTED_PROVENANCE.verifierAddress),
      ),
      EXPECTED_FROZEN.runtimeCodehash,
    );
    await verifier.verifyProof(vector.programVKey, vector.publicValues, vector.proof);
  });

  it("rejects one-byte mutations of the vkey, public values, and proof", async () => {
    const verifier = await installFrozenVerifierRuntime();
    const mutations = [
      [mutateLastByte(vector.programVKey), vector.publicValues, vector.proof],
      [vector.programVKey, mutateLastByte(vector.publicValues), vector.proof],
      [vector.programVKey, vector.publicValues, mutateLastByte(vector.proof)],
    ];
    for (const args of mutations) {
      await assert.rejects(verifier.verifyProof(...args));
    }
  });
});
