#!/usr/bin/env node
// Dedicated resolver rerun authority. It accepts immutable references only;
// solution bytes, runner transcripts, timing, and job metadata are produced here.

import { createHash } from "node:crypto";
import {
  chmodSync, closeSync, constants, existsSync, fsyncSync, linkSync,
  lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, unlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { ethers } from "ethers";

import { findTxidByCid, fetchFromArweave } from "./da-arweave.mjs";
import { canonicalJson, recoverRevealCalldata, sha256Canonical } from "./lib.mjs";
import { readCredentialJson, readCredentialUrl } from "./runtime-credentials.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";

export const RESOLVER_RERUN_REQUEST_SCHEMA = "p42-resolver-rerun-request/v1";
const REQUEST_TRUST_CREDENTIAL = "/run/credentials/p42/resolver-rerun-request-trust";
const DEFAULT_RESULT_ROOT = "/var/lib/p42/resolver-rerun-executor/results";
const DEFAULT_EXECUTOR_SOCKET = "/run/p42-verifier-executor/executor.sock";
const MAX_RERUN_EXECUTION_ATTEMPTS = 16;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const BYTES32_RE = /^0x[0-9a-f]{64}$/;
const ADDRESS_RE = /^0x[0-9a-f]{40}$/;
const REVEAL_ABI = [
  "function reveal(uint256 submissionId,string solutionCid,int256 claimedScoreAtoms,uint256 improvementAtoms,string salt,bytes solution)",
];

function requestSigningMessage(requestHash) {
  return ethers.concat([ethers.toUtf8Bytes("P42-RESOLVER-RERUN-REQUEST-V1\0"), `0x${requestHash.slice(7)}`]);
}

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());
}

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function safeName(value, label) {
  if (!/^[a-z0-9][a-z0-9._:-]{1,191}$/.test(value ?? "")) throw new Error(`${label} is invalid`);
  return value.replaceAll(":", "-");
}

export function resolverRerunResultPaths(resultRoot, request) {
  const directory = join(
    resolve(resultRoot), request.packet_hash.slice(7), request.orchestrator_nonce.slice(2),
  );
  return Object.freeze({
    directory,
    transcript: join(directory, "transcript.json"),
    receipt: join(directory, "receipt.json"),
  });
}

export function resolverRerunExecutorRequestId(requestHash, attempt) {
  if (!SHA256_RE.test(requestHash ?? "") || !Number.isSafeInteger(attempt) || attempt < 0) {
    throw new Error("resolver rerun executor request identity is invalid");
  }
  return sha256Canonical({
    schema_version: "p42-resolver-rerun-executor-request-id/v1",
    request_hash: requestHash,
    attempt,
  });
}

export function validateResolverRerunRequest(value, options = {}) {
  const keys = [
    "schema_version", "packet_hash", "decision_digest", "challenge_instance_hash",
    "orchestrator_nonce", "issued_at_utc", "expires_at_utc", "quorum", "manager", "board_id", "manifest_path",
    "manifest_sha256", "published_transcript_hash", "chain_claim", "request_hash", "request_authorization",
  ];
  if (!exactKeys(value, keys) || value.schema_version !== RESOLVER_RERUN_REQUEST_SCHEMA) {
    throw new Error("resolver rerun request has unknown or missing fields");
  }
  if (!SHA256_RE.test(value.packet_hash) || !BYTES32_RE.test(value.decision_digest)
      || !BYTES32_RE.test(value.challenge_instance_hash) || !BYTES32_RE.test(value.orchestrator_nonce)
      || !ADDRESS_RE.test(value.quorum) || !ADDRESS_RE.test(value.manager)
      || !SHA256_RE.test(value.manifest_sha256) || !SHA256_RE.test(value.published_transcript_hash)
      || !resolve(value.manifest_path).startsWith(`${resolve(options.manifestRoot ?? "/opt/p42")}/`) || !value.chain_claim
      || typeof value.chain_claim !== "object" || Array.isArray(value.chain_claim)
      || !Number.isFinite(Date.parse(value.issued_at_utc)) || !Number.isFinite(Date.parse(value.expires_at_utc))
      || Date.parse(value.expires_at_utc) <= Date.parse(value.issued_at_utc)) {
    throw new Error("resolver rerun request immutable bindings are malformed");
  }
  safeName(value.board_id, "resolver rerun board id");
  const unsigned = Object.fromEntries(Object.entries(value).filter(([key]) => !["request_hash", "request_authorization"].includes(key)));
  if (value.request_hash !== sha256Canonical(unsigned)) throw new Error("resolver rerun request self-hash mismatch");
  const authorization = value.request_authorization;
  if (!exactKeys(authorization, ["algorithm", "signer", "signature"])
      || authorization.algorithm !== "eip191" || !ADDRESS_RE.test(authorization.signer)
      || !/^0x[0-9a-f]{130}$/.test(authorization.signature ?? "")) {
    throw new Error("resolver rerun request authorization is malformed");
  }
  const recovered = ethers.verifyMessage(requestSigningMessage(value.request_hash), authorization.signature).toLowerCase();
  if (recovered !== authorization.signer || (options.requestSignerAddress
      && recovered !== String(options.requestSignerAddress).toLowerCase())) {
    throw new Error("resolver rerun request signer is not the pinned signer authority");
  }
  return Object.freeze(structuredClone(value));
}

export function buildResolverRerunRequest({ packet, challenge, boardId, manifestPath, manifestBytes, publishedTranscript, manifestRoot, requestSignerPrivateKey }) {
  if (challenge.packet_hash !== packet.packet_hash || challenge.decision_digest !== packet.decision_digest
      || challenge.challenge_instance_hash !== packet.decision.challengeInstanceHash) {
    throw new Error("resolver rerun challenge does not bind the packet");
  }
  if (publishedTranscript.transcript_hash !== `sha256:${packet.decision.transcriptHash.slice(2)}`) {
    throw new Error("published transcript does not match the resolver packet");
  }
  const unsigned = {
    schema_version: RESOLVER_RERUN_REQUEST_SCHEMA,
    packet_hash: packet.packet_hash,
    decision_digest: packet.decision_digest,
    challenge_instance_hash: packet.decision.challengeInstanceHash,
    orchestrator_nonce: challenge.orchestrator_nonce,
    issued_at_utc: challenge.issued_at_utc,
    expires_at_utc: challenge.expires_at_utc,
    quorum: packet.decision.adapter,
    manager: packet.decision.manager,
    board_id: boardId,
    manifest_path: resolve(manifestPath),
    manifest_sha256: sha256Bytes(manifestBytes),
    published_transcript_hash: publishedTranscript.transcript_hash,
    chain_claim: structuredClone(publishedTranscript.verifier.chain_claim),
  };
  if (!/^0x[0-9a-fA-F]{64}$/.test(requestSignerPrivateKey ?? "")) {
    throw new Error("resolver rerun request requires the pinned signer private key");
  }
  const requestHash = sha256Canonical(unsigned);
  const wallet = new ethers.Wallet(requestSignerPrivateKey);
  const request = {
    ...unsigned,
    request_hash: requestHash,
    request_authorization: {
      algorithm: "eip191", signer: wallet.address.toLowerCase(),
      signature: wallet.signMessageSync(requestSigningMessage(requestHash)).toLowerCase(),
    },
  };
  return validateResolverRerunRequest(request, { manifestRoot, requestSignerAddress: wallet.address });
}

function validateRequestTrust(value) {
  if (!exactKeys(value, ["schema_version", "purpose", "algorithm", "signer"])
      || value.schema_version !== "p42-resolver-rerun-request-trust/v1"
      || value.purpose !== "resolver-rerun-request" || value.algorithm !== "eip191"
      || !ADDRESS_RE.test(value.signer ?? "")) {
    throw new Error("resolver rerun request trust credential is malformed");
  }
  return value;
}

export async function materializeResolverSolution(request, { provider, findTxid = findTxidByCid, fetchArweave = fetchFromArweave }) {
  const claim = request.chain_claim;
  const expected = `sha256:${String(claim.commit_da_hash).slice(2).toLowerCase()}`;
  let bytes;
  if (Number(claim.solution_bytes_length) > 0) {
    const txHash = claim.reveal_transaction_hash ?? claim.transaction_hash;
    const tx = await provider.getTransaction(txHash);
    if (!tx?.data) throw new Error("resolver rerun could not independently retrieve reveal calldata");
    const recovered = recoverRevealCalldata(tx.data, new ethers.Interface(REVEAL_ABI), {
      submissionId: claim.submission_id,
      solutionCid: claim.solution_cid,
      claimedScoreAtoms: claim.claimed_score_atoms,
      improvementAtoms: claim.claimed_improvement_atoms,
      solutionBytesLength: claim.solution_bytes_length,
      commitDaHash: claim.commit_da_hash,
    });
    bytes = Buffer.from(ethers.getBytes(recovered.solution));
  } else {
    const txid = await findTxid(claim.solution_cid, {});
    if (!txid) throw new Error("resolver rerun could not independently locate off-chain solution bytes");
    bytes = Buffer.from(await fetchArweave(txid, {}));
  }
  if (sha256Bytes(bytes) !== expected) throw new Error("resolver rerun materialized solution does not match commitDaHash");
  return bytes;
}

function productionBridge({ socket, boardId, transcriptDir }) {
  return (request) => {
    const args = ["--socket", socket, "--board-id", boardId, "--transcript-dir", transcriptDir];
    if (request.operation === "rerun-enqueue") args.push("--rerun-enqueue", "--request-hash", request.request_hash,
      "--chain-now-utc", request.chain_now_utc);
    else if (request.operation === "rerun-execute") args.push("--rerun-execute", "--request-hash", request.request_hash,
      "--attempt", String(request.attempt), "--chain-timestamp", request.chain_timestamp);
    else if (["rerun-attest", "rerun-recover"].includes(request.operation)) args.push(
      request.operation === "rerun-attest" ? "--rerun-attest" : "--rerun-recover", "--request-hash", request.request_hash,
    );
    else throw new Error("resolver rerun client operation is not allowed");
    const executable = new URL("./verifier-executor-client.py", import.meta.url).pathname;
    const completed = spawnSync(process.env.P42_RUNTIME_PYTHON || "python3", [executable, ...args], {
      encoding: "utf8", maxBuffer: 16 * 1024 * 1024,
    });
    if (completed.status !== 0) throw new Error((completed.stderr || completed.stdout).trim());
    return JSON.parse(completed.stdout);
  };
}

function fsyncDirectory(path, io) {
  const descriptor = io.openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { io.fsyncSync(descriptor); } finally { io.closeSync(descriptor); }
}

export function ensureDurableDirectoryPath(pathValue, mode = 0o750, injectedIo = {}) {
  const io = {
    closeSync: injectedIo.closeSync ?? closeSync,
    existsSync: injectedIo.existsSync ?? existsSync,
    fsyncSync: injectedIo.fsyncSync ?? fsyncSync,
    lstatSync: injectedIo.lstatSync ?? lstatSync,
    mkdirSync: injectedIo.mkdirSync ?? mkdirSync,
    openSync: injectedIo.openSync ?? openSync,
  };
  const target = resolve(pathValue);
  const missing = [];
  let cursor = target;
  while (!io.existsSync(cursor)) {
    missing.push(cursor);
    const parent = dirname(cursor);
    if (parent === cursor) throw new Error("resolver rerun durable directory has no existing ancestor");
    cursor = parent;
  }
  const ancestor = io.lstatSync(cursor);
  if (!ancestor.isDirectory() || ancestor.isSymbolicLink()) throw new Error("resolver rerun durable ancestor is unsafe");
  for (const path of missing.reverse()) {
    const parent = dirname(path);
    io.mkdirSync(path, { mode });
    const metadata = io.lstatSync(path);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== mode) {
      throw new Error("resolver rerun durable directory creation is unsafe");
    }
    fsyncDirectory(path, io);
    fsyncDirectory(parent, io);
  }
  return target;
}

export function writeResolverRerunResult(path, value, injectedIo = {}) {
  const io = {
    closeSync: injectedIo.closeSync ?? closeSync,
    existsSync: injectedIo.existsSync ?? existsSync,
    fsyncSync: injectedIo.fsyncSync ?? fsyncSync,
    linkSync: injectedIo.linkSync ?? linkSync,
    lstatSync: injectedIo.lstatSync ?? lstatSync,
    mkdirSync: injectedIo.mkdirSync ?? mkdirSync,
    openSync: injectedIo.openSync ?? openSync,
    readFileSync: injectedIo.readFileSync ?? readFileSync,
    unlinkSync: injectedIo.unlinkSync ?? unlinkSync,
    writeFileSync: injectedIo.writeFileSync ?? writeFileSync,
  };
  const directory = dirname(path);
  ensureDurableDirectoryPath(directory, 0o750, io);
  const payload = `${canonicalJson(value)}\n`;
  if (io.existsSync(path)) {
    if (io.readFileSync(path, "utf8") !== payload) throw new Error("resolver rerun result conflicts with durable output");
    const existing = io.openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { io.fsyncSync(existing); } finally { io.closeSync(existing); }
    fsyncDirectory(directory, io);
    return;
  }
  const temporary = `${path}.tmp-${process.pid}`;
  const descriptor = io.openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o640);
  try {
    io.writeFileSync(descriptor, payload);
    io.fsyncSync(descriptor);
  } finally {
    io.closeSync(descriptor);
  }
  try {
    io.linkSync(temporary, path);
    fsyncDirectory(directory, io);
  } catch (error) {
    if (error.code !== "EEXIST" || io.readFileSync(path, "utf8") !== payload) throw error;
    const existing = io.openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { io.fsyncSync(existing); } finally { io.closeSync(existing); }
    fsyncDirectory(directory, io);
  } finally {
    io.unlinkSync(temporary);
    fsyncDirectory(directory, io);
  }
}

function writeDurableStagingFile(path, bytes, mode) {
  const directory = dirname(path);
  const payload = Buffer.from(bytes);
  if (existsSync(path)) {
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
        || metadata.uid !== process.getuid() || (metadata.mode & 0o777) !== mode
        || !readFileSync(path).equals(payload)) {
      throw new Error("resolver rerun durable staging artifact conflicts with the request");
    }
    const existing = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { fsyncSync(existing); } finally { closeSync(existing); }
    fsyncDirectory(directory, { openSync, fsyncSync, closeSync });
    return;
  }
  const temporary = `${path}.tmp-${process.pid}`;
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  try { writeFileSync(fd, payload); fsyncSync(fd); } finally { closeSync(fd); }
  try { renameSync(temporary, path); fsyncDirectory(directory, { openSync, fsyncSync, closeSync }); }
  finally { if (existsSync(temporary)) unlinkSync(temporary); }
}

function validateRerunTranscript(transcript, { job, request, solutionHash }) {
  if (transcript.job_id !== job.job_id || transcript.transcript_hash !== sha256Canonical(
    Object.fromEntries(Object.entries(transcript).filter(([key]) => key !== "transcript_hash")),
  ) || transcript.verifier?.report?.solution_hash !== solutionHash
      || transcript.da?.expected_hash !== solutionHash || transcript.da?.observed_hash !== solutionHash
      || canonicalJson(transcript.verifier?.chain_claim) !== canonicalJson(request.chain_claim)
      || transcript.board_identity?.verifier_image !== request.chain_claim.registry_binding?.verifier_image
      || transcript.board_identity?.verifier_source_sha256 !== request.chain_claim.registry_binding?.verifier_source_digest
      || !SHA256_RE.test(transcript.board_identity?.resource_identity ?? "")) {
    throw new Error("resolver rerun executor received a malformed or substituted transcript");
  }
  return transcript;
}

export async function executeResolverRerun(requestValue, options = {}) {
  const requestTrust = validateRequestTrust(options.requestTrust ?? readCredentialJson(
    options.requestTrustPath ?? process.env.P42_RESOLVER_RERUN_REQUEST_TRUST ?? REQUEST_TRUST_CREDENTIAL,
    "resolver rerun request trust",
  ));
  const request = validateResolverRerunRequest(requestValue, {
    manifestRoot: options.manifestRoot, requestSignerAddress: requestTrust.signer,
  });
  const requestExpired = (options.now ?? Date.now()) >= Date.parse(request.expires_at_utc);
  const manifestBytes = options.manifestBytes ?? readFileSync(request.manifest_path);
  if (sha256Bytes(manifestBytes) !== request.manifest_sha256) throw new Error("resolver rerun manifest digest changed");
  const provider = options.provider ?? new ethers.JsonRpcProvider(options.rpcUrl);
  const solution = await materializeResolverSolution(request, { provider, ...options });
  const paths = resolverRerunResultPaths(options.resultRoot ?? DEFAULT_RESULT_ROOT, request);
  const stagingParent = resolve(options.stagingRoot ?? tmpdir());
  ensureDurableDirectoryPath(stagingParent, 0o750, options.directoryIo);
  const staging = join(stagingParent, request.request_hash.slice(7));
  ensureDurableDirectoryPath(staging, 0o750, options.directoryIo);
  chmodSync(staging, 0o750);
  const stagingMetadata = lstatSync(staging);
  if (!stagingMetadata.isDirectory() || stagingMetadata.isSymbolicLink()
      || stagingMetadata.uid !== process.getuid() || (stagingMetadata.mode & 0o777) !== 0o750) {
    throw new Error("resolver rerun durable staging directory authority mismatch");
  }
  let completedDurably = false;
  try {
    const solutionPath = join(staging, "solution.bin");
    writeDurableStagingFile(solutionPath, solution, 0o640);
    const job = {
      job_id: `resolver-rerun:${request.packet_hash.slice(7)}:${request.orchestrator_nonce.slice(2)}`,
      status: "queued",
      created_at_utc: request.issued_at_utc,
      source_event_hash: sha256Canonical({
        schema_version: "p42-resolver-rerun-job/v1", request_hash: request.request_hash,
        solution_hash: sha256Bytes(solution),
      }),
      chain_block_number: Number(request.chain_claim.block_number),
      chain_log_index: Number(request.chain_claim.log_index),
      chain_claim: request.chain_claim,
      challenge_policy: { max_bond_wei: "0" },
      solution: solutionPath,
    };
    writeDurableStagingFile(join(staging, "job.json"), Buffer.from(`${canonicalJson(job)}\n`), 0o640);
    const transcriptContext = { job, request, solutionHash: sha256Bytes(solution) };
    let transcript = null;
    let receipt = null;
    const transcriptDir = join(staging, "transcripts");
    const bridge = options.bridge ?? productionBridge({
      socket: options.socket ?? DEFAULT_EXECUTOR_SOCKET, boardId: request.board_id, transcriptDir,
    });
    let attestation = bridge({ operation: "rerun-recover", request_hash: request.request_hash });
    if (attestation.status === "attested") {
      transcript = readStrictJsonFileSync(attestation.transcript_path, {
        maxBytes: 16 * 1024 * 1024, maxDepth: 64, canonicalBytes: true, trailingNewline: "require",
      });
      validateRerunTranscript(transcript, transcriptContext);
      receipt = attestation.receipt;
    }
    if (requestExpired && !transcript) throw new Error("resolver rerun request expired before execution");
    let admissionBlock;
    if (!receipt) {
      admissionBlock = await provider.getBlock("finalized");
      if (!admissionBlock?.timestamp) throw new Error("resolver rerun RPC has no finalized chain timestamp");
      const chainNowUtc = new Date(Number(admissionBlock.timestamp) * 1000).toISOString();
      bridge({ operation: "rerun-enqueue", request_hash: request.request_hash, chain_now_utc: chainNowUtc });
      options.crash?.("after-enqueue", { request, job, staging });
    }
    const maxRuns = options.maxRuns ?? MAX_RERUN_EXECUTION_ATTEMPTS;
    if (!Number.isSafeInteger(maxRuns) || maxRuns < 1 || maxRuns > MAX_RERUN_EXECUTION_ATTEMPTS) {
      throw new Error("resolver rerun execution attempt limit exceeds the host ceiling");
    }
    for (let attempt = 0; !receipt && attempt < maxRuns; attempt += 1) {
      const block = attempt === 0 ? admissionBlock : await provider.getBlock("finalized");
      if (!block?.timestamp) throw new Error("resolver rerun RPC has no finalized chain timestamp");
      bridge({
        operation: "rerun-execute", request_hash: request.request_hash, attempt,
        chain_timestamp: String(block.timestamp),
      });
      attestation = bridge({ operation: "rerun-attest", request_hash: request.request_hash });
      if (attestation.status === "attested") {
        transcript = readStrictJsonFileSync(attestation.transcript_path, {
          maxBytes: 16 * 1024 * 1024, maxDepth: 64, canonicalBytes: true, trailingNewline: "require",
        });
        validateRerunTranscript(transcript, transcriptContext);
        writeDurableStagingFile(join(staging, "transcript.json"), Buffer.from(`${canonicalJson(transcript)}\n`), 0o640);
        receipt = attestation.receipt;
        options.crash?.("after-transcript-durable", { request, job, staging, transcript });
        break;
      }
      await (options.sleep ?? ((ms) => new Promise((done) => setTimeout(done, ms))))(options.pollMs ?? 1000);
    }
    if (!transcript || !receipt) throw new Error("resolver rerun did not complete before the execution attempt limit");
    validateRerunTranscript(transcript, transcriptContext);
    writeResolverRerunResult(paths.transcript, transcript, options.resultIo);
    writeResolverRerunResult(paths.receipt, receipt, options.resultIo);
    completedDurably = true;
    return { request, transcript, receipt, paths };
  } finally {
    if (completedDurably) rmSync(staging, { recursive: true, force: true });
    provider.destroy?.();
  }
}

function arg(argv, name, fallback = undefined) {
  const index = argv.indexOf(`--${name}`);
  return index >= 0 ? argv[index + 1] : fallback;
}

export async function main(argv = process.argv.slice(2)) {
  const requestPath = arg(argv, "request");
  const rpcUrl = arg(argv, "rpc") ?? (arg(argv, "rpc-url-file")
    ? readCredentialUrl(resolve(arg(argv, "rpc-url-file")), "resolver rerun RPC URL")
    : null);
  if (!requestPath || !rpcUrl) throw new Error("required: --request and one of --rpc or --rpc-url-file");
  const request = readStrictJsonFileSync(resolve(requestPath), {
    maxBytes: 256 * 1024, maxDepth: 32, canonicalBytes: true, trailingNewline: "require",
  });
  const result = await executeResolverRerun(request, {
    rpcUrl, resultRoot: arg(argv, "result-root", DEFAULT_RESULT_ROOT),
    stagingRoot: arg(argv, "staging-root"),
    requestTrustPath: arg(argv, "request-trust-file"),
  });
  console.log(canonicalJson({ status: "rerun-complete", request_hash: request.request_hash, ...result.paths }));
}

const invokedPath = process.argv[1] ? pathToFileURL(realpathSync(resolve(process.argv[1]))).href : null;
if (invokedPath === import.meta.url) main().catch((error) => { console.error("FAILED:", error.message); process.exitCode = 1; });
