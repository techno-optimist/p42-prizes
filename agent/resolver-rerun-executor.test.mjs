import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  closeSync, constants, existsSync, fsyncSync, linkSync, mkdirSync, mkdtempSync, openSync,
  lstatSync, readFileSync, rmSync, unlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { ethers } from "ethers";

import { canonicalJson, sha256Canonical } from "./lib.mjs";
import {
  buildResolverRerunRequest,
  ensureDurableDirectoryPath,
  executeResolverRerun,
  resolverRerunExecutorRequestId,
  validateResolverRerunRequest,
  writeResolverRerunResult,
} from "./resolver-rerun-executor.mjs";

const HASH = (digit) => `0x${digit.repeat(64)}`;
const SHA = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const ADDR = {
  submissions: "0x1111111111111111111111111111111111111111",
  challenges: "0x2222222222222222222222222222222222222222",
  quorum: "0x3333333333333333333333333333333333333333",
};
const REQUEST_SIGNER_KEY = `0x${"42".repeat(32)}`;
const REQUEST_SIGNER = new ethers.Wallet(REQUEST_SIGNER_KEY).address.toLowerCase();

test("resolver rerun results are file-and-directory durable before success", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-rerun-result-durable-"));
  const path = join(root, "packet", "nonce", "receipt.json");
  const events = [];
  const descriptors = new Map();
  try {
    writeResolverRerunResult(path, { ok: true }, {
      openSync(name, flags, mode) {
        const fd = openSync(name, flags, mode);
        descriptors.set(fd, String(name));
        return fd;
      },
      closeSync(fd) { descriptors.delete(fd); closeSync(fd); },
      fsyncSync(fd) { events.push(`fsync:${descriptors.get(fd)}`); fsyncSync(fd); },
      linkSync(source, target) { events.push(`link:${target}`); linkSync(source, target); },
      unlinkSync(name) { events.push(`unlink:${name}`); unlinkSync(name); },
    });
    const link = events.findIndex((item) => item.startsWith("link:"));
    const fileFsync = events.findIndex((item) => item.includes("receipt.json.tmp-"));
    const directoryFsync = events.findIndex((item, index) => index > link && item === `fsync:${join(root, "packet", "nonce")}`);
    assert.ok(fileFsync >= 0 && fileFsync < link);
    assert.ok(directoryFsync > link);
    assert.equal(readFileSync(path, "utf8"), "{\"ok\":true}\n");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("every new staging/result ancestor is fsynced child-before-parent and crash replayable", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-rerun-ancestor-fsync-"));
  const target = join(root, "packet", "nonce");
  const events = [];
  const descriptors = new Map();
  const io = {
    openSync(path, flags, mode) { const fd = openSync(path, flags, mode); descriptors.set(fd, String(path)); return fd; },
    closeSync(fd) { descriptors.delete(fd); closeSync(fd); },
    mkdirSync(path, options) { events.push(`mkdir:${path}`); mkdirSync(path, options); },
    fsyncSync(fd) { events.push(`fsync:${descriptors.get(fd)}`); fsyncSync(fd); },
  };
  try {
    ensureDurableDirectoryPath(target, 0o750, io);
    assert.deepEqual(events, [
      `mkdir:${join(root, "packet")}`, `fsync:${join(root, "packet")}`, `fsync:${root}`,
      `mkdir:${target}`, `fsync:${target}`, `fsync:${join(root, "packet")}`,
    ]);
    rmSync(join(root, "packet"), { recursive: true, force: true });
    let failed = false;
    assert.throws(() => ensureDurableDirectoryPath(target, 0o750, {
      ...io, fsyncSync(fd) {
        if (!failed && descriptors.get(fd) === root) { failed = true; throw new Error("power cut before parent durability"); }
        fsyncSync(fd);
      },
    }), /power cut/);
    rmSync(join(root, "packet"), { recursive: true, force: true });
    ensureDurableDirectoryPath(target, 0o750);
    assert.equal(lstatSync(target).isDirectory(), true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("resolver rerun result publication never reports success across a directory fsync failure", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-rerun-result-crash-"));
  const path = join(root, "packet", "nonce", "receipt.json");
  let directoryDescriptor = -1;
  try {
    assert.throws(() => writeResolverRerunResult(path, { ok: true }, {
      openSync(name, flags, mode) {
        const fd = openSync(name, flags, mode);
        if ((flags & constants.O_DIRECTORY) !== 0) directoryDescriptor = fd;
        return fd;
      },
      fsyncSync(fd) {
        if (fd === directoryDescriptor) throw Object.assign(new Error("injected directory fsync failure"), { code: "EIO" });
        fsyncSync(fd);
      },
    }), /injected directory fsync failure/);
    writeResolverRerunResult(path, { ok: true });
    assert.equal(readFileSync(path, "utf8"), "{\"ok\":true}\n");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function setup(root) {
  const solution = Buffer.from("independent exact resolver rerun\n");
  const solutionHash = SHA(solution);
  const iface = new ethers.Interface([
    "function reveal(uint256 submissionId,string solutionCid,int256 claimedScoreAtoms,uint256 improvementAtoms,string salt,bytes solution)",
  ]);
  const transactionData = iface.encodeFunctionData("reveal", [17, solutionHash, 2, 1, "salt", solution]);
  const chainClaim = {
    schema_version: "p42-chain-claim/v1", chain_id: 84532, problem_id: "hadamard-mini",
    submission_contract: ADDR.submissions, challenge_contract: ADDR.challenges,
    submission_id: "17", block_number: 100, block_hash: HASH("1"),
    transaction_hash: HASH("2"), transaction_index: 0, log_index: 4,
    solver: ADDR.quorum, solution_cid: solutionHash,
    commit_da_hash: `0x${solutionHash.slice(7)}`, claimed_score_atoms: "2",
    claimed_improvement_atoms: "1", reveal_instance_hash: HASH("3"),
    challenge_ends_at: "2000000000", solution_bytes_length: solution.length, onchain_da: true,
    registry_binding: {
      verifier_image: SHA(Buffer.from("image")), verifier_source_digest: SHA(Buffer.from("source")),
    },
  };
  const publishedBody = {
    schema_version: "p42-runner-transcript/v1", job_id: "published", generated_at_utc: "2026-07-10T00:00:00Z",
    started_at_utc: "2026-07-10T00:00:00Z", problem: "/opt/p42/problems/hadamard-mini",
    board_identity: { resource_identity: SHA(Buffer.from("resources")) }, solution: "/published/solution",
    da: { ok: true, expected_hash: solutionHash, observed_hash: solutionHash },
    verifier: { report: { solution_hash: solutionHash }, chain_claim: chainClaim },
  };
  const publishedTranscript = { ...publishedBody, transcript_hash: sha256Canonical(publishedBody) };
  const packet = {
    packet_hash: SHA(Buffer.from("packet")), decision_digest: HASH("4"),
    decision: {
      transcriptHash: `0x${publishedTranscript.transcript_hash.slice(7)}`,
      challengeInstanceHash: HASH("5"), adapter: ADDR.quorum, manager: ADDR.challenges,
    },
  };
  const challenge = {
    packet_hash: packet.packet_hash, decision_digest: packet.decision_digest,
    challenge_instance_hash: packet.decision.challengeInstanceHash, orchestrator_nonce: HASH("6"),
    issued_at_utc: "2026-07-10T00:00:00Z", expires_at_utc: "2026-07-10T00:15:00Z",
  };
  const manifestPath = join(root, "release", "manifest.json");
  const manifestBytes = Buffer.from("{}\n");
  mkdirSync(join(root, "release"), { recursive: true });
  writeFileSync(manifestPath, manifestBytes);
  const request = buildResolverRerunRequest({
    packet, challenge, boardId: "84532:1:hadamard-mini", manifestPath, manifestBytes,
    publishedTranscript, manifestRoot: root, requestSignerPrivateKey: REQUEST_SIGNER_KEY,
  });
  return { solution, solutionHash, transactionData, chainClaim, request };
}

function hostAttestation(value, root) {
  const jobId = `resolver-rerun:${value.request.packet_hash.slice(7)}:${value.request.orchestrator_nonce.slice(2)}`;
  const solution = join(root, "staging", value.request.request_hash.slice(7), "solution.bin");
  const body = { schema_version: "p42-runner-transcript/v1", job_id: jobId,
    generated_at_utc: "2026-07-10T00:00:01Z", started_at_utc: "2026-07-10T00:00:01Z",
    problem: "/opt/p42/problems/hadamard-mini",
    board_identity: { resource_identity: SHA(Buffer.from("resources")),
      verifier_image: value.chainClaim.registry_binding.verifier_image,
      verifier_source_sha256: value.chainClaim.registry_binding.verifier_source_digest },
    solution, da: { ok: true, expected_hash: value.solutionHash, observed_hash: value.solutionHash },
    verifier: { elapsed_ms: 19, report: { solution_hash: value.solutionHash }, chain_claim: value.chainClaim } };
  const transcript = { ...body, transcript_hash: sha256Canonical(body) };
  const transcriptPath = join(root, "host-transcript.json");
  writeFileSync(transcriptPath, `${canonicalJson(transcript)}\n`, { mode: 0o640 });
  const receipt = { schema_version: "p42-resolver-rerun/v1", executor_key_id: "host-attestor",
    algorithm: "ed25519", packet_hash: value.request.packet_hash, decision_digest: value.request.decision_digest,
    chain_id: String(value.chainClaim.chain_id), quorum: value.request.quorum, manager: value.request.manager,
    submission_id: String(value.chainClaim.submission_id), challenge_instance_hash: value.request.challenge_instance_hash,
    reveal_instance_hash: value.chainClaim.reveal_instance_hash, published_transcript_hash: value.request.published_transcript_hash,
    solution_hash: value.solutionHash, da_expected_hash: value.solutionHash, da_observed_hash: value.solutionHash,
    verifier_image: value.chainClaim.registry_binding.verifier_image,
    verifier_source_digest: value.chainClaim.registry_binding.verifier_source_digest,
    resource_identity: transcript.board_identity.resource_identity, orchestrator_nonce: value.request.orchestrator_nonce,
    local_transcript_hash: transcript.transcript_hash, receipt_hash: SHA(Buffer.from("receipt")),
    signature: { algorithm: "ed25519", key_id: "host-attestor", signature: `ed25519:${"aa".repeat(64)}` } };
  return { status: "attested", location: "archive", transcript_path: transcriptPath, transcript, receipt };
}

test("rerun request rejects caller transcripts and caller-owned run metadata", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-rerun-request-"));
  try {
    const { request } = setup(root);
    for (const injected of [
      { local_transcript: { copied: true } }, { elapsed_ms: 1 }, { job_id: "caller-job" },
    ]) {
      assert.throws(
        () => validateResolverRerunRequest({ ...request, ...injected }, { manifestRoot: root }),
        /unknown or missing fields/,
      );
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rerun client uses only dedicated request-bound executor operations", async () => {
  const root = mkdtempSync(join(tmpdir(), "p42-rerun-restart-"));
  try {
    const value = setup(root);
    const operations = [];
    const attestation = hostAttestation(value, root);
    let executed = false;
    const bridge = (message) => {
      operations.push(structuredClone(message));
      if (message.operation === "rerun-recover") return { status: "pending" };
      if (message.operation === "rerun-enqueue") return { created: true };
      if (message.operation === "rerun-execute") { executed = true; return { selected_job_id: attestation.transcript.job_id }; }
      if (message.operation === "rerun-attest") return executed ? attestation : { status: "pending" };
      throw new Error("generic executor bridge reached");
    };
    const provider = { getTransaction: async () => ({ data: value.transactionData }),
      getBlock: async () => ({ timestamp: 1_783_667_101 }) };
    const options = {
      manifestRoot: root, manifestBytes: Buffer.from("{}\n"), provider, bridge,
      resultRoot: join(root, "results"), stagingRoot: join(root, "staging"),
      now: Date.parse("2026-07-10T00:05:00Z"),
      requestTrust: { schema_version: "p42-resolver-rerun-request-trust/v1", purpose: "resolver-rerun-request",
        algorithm: "eip191", signer: REQUEST_SIGNER },
    };
    const result = await executeResolverRerun(value.request, options);
    assert.equal(result.receipt, attestation.receipt);
    assert.deepEqual(operations.map((item) => item.operation), [
      "rerun-recover", "rerun-enqueue", "rerun-execute", "rerun-attest",
    ]);
    assert.ok(operations.every((item) => !item.job && !item.arguments && !item.transcript && !item.receipt));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("restart completes from executor archive attestation after crash before result writes", async () => {
  const root = mkdtempSync(join(tmpdir(), "p42-rerun-transcript-recovery-"));
  try {
    const value = setup(root);
    const attestation = hostAttestation(value, root);
    let first = true;
    const bridge = (message) => {
      if (message.operation === "rerun-recover") return first ? { status: "pending" } : attestation;
      if (message.operation === "rerun-enqueue") return { created: true };
      if (message.operation === "rerun-execute") return {};
      if (message.operation === "rerun-attest") { first = false; return attestation; }
      throw new Error("unexpected operation");
    };
    const provider = { getTransaction: async () => ({ data: value.transactionData }),
      getBlock: async () => ({ timestamp: 1_783_667_101 }) };
    const options = { manifestRoot: root, manifestBytes: Buffer.from("{}\n"), provider,
      resultRoot: join(root, "results"), stagingRoot: join(root, "staging"), now: Date.parse("2026-07-10T00:05:00Z"),
      requestTrust: { schema_version: "p42-resolver-rerun-request-trust/v1", purpose: "resolver-rerun-request",
        algorithm: "eip191", signer: REQUEST_SIGNER } };
    await assert.rejects(executeResolverRerun(value.request, { ...options, bridge,
      crash(point) { if (point === "after-transcript-durable") throw new Error("crash before receipt"); } }),
    /crash before receipt/);
    const stable = join(root, "staging", value.request.request_hash.slice(7), "transcript.json");
    assert.equal(JSON.parse(readFileSync(stable)).job_id, attestation.transcript.job_id);
    const result = await executeResolverRerun(value.request, { ...options, now: Date.parse("2026-07-11T00:00:00Z"),
      bridge(message) {
        assert.equal(message.operation, "rerun-recover");
        return attestation;
      } });
    assert.equal(result.receipt.local_transcript_hash, result.transcript.transcript_hash);
    assert.equal(existsSync(join(root, "staging", value.request.request_hash.slice(7))), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("rerun executor request IDs satisfy the host service canonical sha256 contract", () => {
  const requestHash = `sha256:${"ab".repeat(32)}`;
  const first = resolverRerunExecutorRequestId(requestHash, 0);
  const retry = resolverRerunExecutorRequestId(requestHash, 1);
  assert.match(first, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(first, retry);
  assert.equal(first, resolverRerunExecutorRequestId(requestHash, 0));
});

test("rerun request rejects a whole-request substitution signed by an unpinned caller", () => {
  const root = mkdtempSync(join(tmpdir(), "p42-rerun-request-signer-"));
  try {
    const { request } = setup(root);
    const attacker = new ethers.Wallet(`0x${"24".repeat(32)}`);
    const authorization = {
      algorithm: "eip191", signer: attacker.address.toLowerCase(),
      signature: attacker.signMessageSync(ethers.concat([
        ethers.toUtf8Bytes("P42-RESOLVER-RERUN-REQUEST-V1\0"), `0x${request.request_hash.slice(7)}`,
      ])).toLowerCase(),
    };
    assert.throws(
      () => validateResolverRerunRequest(
        { ...request, request_authorization: authorization },
        { manifestRoot: root, requestSignerAddress: REQUEST_SIGNER },
      ),
      /not the pinned signer authority/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("constrained executor materializes bytes and signs only its queued transcript", async () => {
  const root = mkdtempSync(join(tmpdir(), "p42-rerun-executor-"));
  try {
    const value = setup(root);
    const attestation = hostAttestation(value, root);
    let executed = false;
    const bridge = (message) => {
      if (message.operation === "rerun-recover") return { status: "pending" };
      if (message.operation === "rerun-enqueue") return { created: true };
      if (message.operation === "rerun-execute") { executed = true; return {}; }
      if (message.operation === "rerun-attest" && executed) return attestation;
      return { status: "pending" };
    };
    const provider = {
      getTransaction: async () => ({ data: value.transactionData }),
      getBlock: async () => ({ timestamp: 1_783_667_101 }),
    };
    const result = await executeResolverRerun(value.request, {
      manifestRoot: root, manifestBytes: Buffer.from("{}\n"), provider, bridge,
      resultRoot: join(root, "results"), stagingRoot: root, now: Date.parse("2026-07-10T00:05:00Z"),
      requestTrust: {
        schema_version: "p42-resolver-rerun-request-trust/v1", purpose: "resolver-rerun-request",
        algorithm: "eip191", signer: REQUEST_SIGNER,
      },
    });
    assert.equal(result.receipt.local_transcript_hash, result.transcript.transcript_hash);
    assert.equal(result.receipt.solution_hash, value.solutionHash);
    assert.equal(result.receipt.orchestrator_nonce, value.request.orchestrator_nonce);
    assert.match(result.receipt.signature.signature, /^ed25519:[0-9a-f]{128}$/);
    assert.equal(result.receipt.executor_key_id, "host-attestor");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
