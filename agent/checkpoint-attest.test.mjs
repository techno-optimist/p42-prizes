import assert from "node:assert/strict";
import test from "node:test";
import { createPublicKey, verify } from "node:crypto";
import { buildCheckpointAttestation } from "./checkpoint-attest.mjs";

test("checkpoint attestation signs the exact checkpoint bytes", () => {
  const bytes = Buffer.from('{"schema":"p42-indexer-checkpoint/v2"}\n');
  const attestation = buildCheckpointAttestation(bytes, "11".repeat(32), "2026-07-12T22:00:00Z");
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(attestation.publicKey.slice(8), "hex")]), format: "der", type: "spki" });
  const message = Buffer.from(`P42-ATTESTATION-V2\n${attestation.schema}\n${attestation.signerRole}\n${attestation.checkpointDigest}\n${attestation.signedAtUtc}`, "ascii");
  assert.equal(verify(null, message, key, Buffer.from(attestation.signature.slice(8), "hex")), true);
  assert.throws(() => buildCheckpointAttestation(Buffer.from("changed"), "AB".repeat(32)), /lowercase/);
});
