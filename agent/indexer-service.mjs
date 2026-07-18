#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  configureIndexerTranscripts,
  runIndexer,
  stableStringify,
  validateMultiBoardCheckpoint,
  writeFileAtomicSync,
} from "./indexer.mjs";
import { readCredentialUrl } from "./runtime-credentials.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";


const CHECKPOINT_LIMITS = Object.freeze({
  maxBytes: 64 * 1024 * 1024,
  maxDepth: 128,
  canonicalBytes: true,
  trailingNewline: "require",
  privateFile: true,
});
const SERVICE_SCHEMA = "p42-prizes/indexer-service-health/v2";
const CHECKPOINT_SCHEMAS = new Set([
  "p42-prizes/indexer-checkpoint/v2",
  "p42-prizes/indexer-checkpoint/v3",
  "p42-prizes/indexer-checkpoint/v4",
]);


function requirePositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${label} must be a positive safe integer`);
  return value;
}


function iso(now) {
  return new Date(now).toISOString().replace(".000Z", "Z");
}


function sanitizedError(error) {
  const raw = String(error?.shortMessage ?? error?.message ?? error ?? "unknown indexer failure");
  return raw
    .replace(/https?:\/\/[^\s"']+/gi, "[redacted-url]")
    .replace(/[\r\n\t]+/g, " ")
    .slice(0, 512);
}


function checkpointSummary(checkpoint) {
  return checkpoint ? {
    schema: checkpoint.schema,
    from_block: checkpoint.range.fromBlock,
    to_block: checkpoint.range.toBlock,
    to_block_hash: checkpoint.range.toBlockHash,
    to_block_timestamp: checkpoint.range.toBlockTimestamp,
    board_count: checkpoint.boards.length,
    reconstruction_ok: checkpoint.reconstruction.ok,
  } : null;
}


function validatePublicationCheckpoint(checkpoint, validator = validateMultiBoardCheckpoint) {
  if (!checkpoint || typeof checkpoint !== "object" || Array.isArray(checkpoint)) {
    throw new Error("indexer service checkpoint must be an object");
  }
  if (!CHECKPOINT_SCHEMAS.has(checkpoint.schema)) {
    throw new Error("indexer service publishes only multi-board checkpoint schemas v2-v4");
  }
  validator(checkpoint);
  if (checkpoint.reconstruction?.complete !== true || checkpoint.reconstruction?.ok !== true) {
    throw new Error("indexer service refuses to publish an incomplete or failed reconstruction");
  }
  return checkpoint;
}


export function monotonicCheckpointDecision(candidate, current = null) {
  if (current === null) return { decision: "advance", priorBlock: null, nextBlock: candidate.range.toBlock };
  if (candidate.schema !== current.schema) {
    throw new Error("indexer service checkpoint schema changed; use an explicit publication cutover");
  }
  if (stableStringify(candidate.manifestBinding) !== stableStringify(current.manifestBinding)) {
    throw new Error("indexer service checkpoint deployment binding changed");
  }
  if (candidate.range.toBlock < current.range.toBlock) {
    throw new Error(
      `indexer service refuses finalized-range regression ${current.range.toBlock} -> ${candidate.range.toBlock}`,
    );
  }
  if (candidate.range.toBlock === current.range.toBlock) {
    if (candidate.range.toBlockHash.toLowerCase() !== current.range.toBlockHash.toLowerCase()) {
      throw new Error("indexer service detected a conflicting hash at the published finalized height");
    }
    if (stableStringify(candidate) !== stableStringify(current)) {
      throw new Error("indexer service detected non-deterministic checkpoint bytes at the same finalized height");
    }
    return { decision: "unchanged", priorBlock: current.range.toBlock, nextBlock: candidate.range.toBlock };
  }
  return { decision: "advance", priorBlock: current.range.toBlock, nextBlock: candidate.range.toBlock };
}


export function publishMonotonicCheckpointSync({
  candidatePath,
  outputPath,
  validator = validateMultiBoardCheckpoint,
  writer = writeFileAtomicSync,
} = {}) {
  const candidate = validatePublicationCheckpoint(
    readStrictJsonFileSync(resolve(candidatePath), CHECKPOINT_LIMITS),
    validator,
  );
  const current = existsSync(resolve(outputPath))
    ? validatePublicationCheckpoint(readStrictJsonFileSync(resolve(outputPath), CHECKPOINT_LIMITS), validator)
    : null;
  const decision = monotonicCheckpointDecision(candidate, current);
  if (decision.decision === "advance") {
    writer(resolve(outputPath), `${stableStringify(candidate)}\n`);
  }
  return { ...decision, checkpoint: candidate };
}


export async function acquireIndexerSingletonLock(lockPath, { spawnImpl = spawn } = {}) {
  const resolvedPath = resolve(lockPath);
  mkdirSync(resolve(resolvedPath, ".."), { recursive: true, mode: 0o700 });
  const descriptor = openSync(resolvedPath, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
  const metadata = fstatSync(descriptor);
  if (!metadata.isFile() || metadata.nlink !== 1) {
    closeSync(descriptor);
    throw new Error("indexer singleton lock must be a single-link regular file");
  }
  // flock follows the inherited open-file description. The helper may exit
  // after acquisition without releasing the lock retained by this descriptor.
  const script = "import fcntl; fcntl.flock(3,fcntl.LOCK_EX|fcntl.LOCK_NB); print('READY',flush=True)";
  let child;
  try {
    child = spawnImpl("/usr/bin/python3", ["-c", script], { stdio: ["ignore", "pipe", "pipe", descriptor] });
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
  return new Promise((resolveLock, rejectLock) => {
    let output = "";
    let errors = "";
    let ready = false;
    let released = false;
    let settled = false;
    const reject = (error) => {
      if (settled) return;
      settled = true;
      closeSync(descriptor);
      rejectLock(error);
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("indexer singleton lock timeout"));
    }, 5000);
    child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { errors += chunk; });
    child.stdout.on("data", (chunk) => {
      output += chunk;
      if (output === "READY\n") ready = true;
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      if (!ready || code !== 0) {
        reject(new Error(`indexer singleton lock unavailable: ${errors.trim() || code}`));
        return;
      }
      settled = true;
      const release = async () => {
        if (released) return;
        released = true;
        closeSync(descriptor);
      };
      release.assertOwned = () => {
        if (released) throw new Error("indexer singleton publication ownership was lost");
        fstatSync(descriptor);
      };
      resolveLock(release);
    });
    child.once("error", (error) => reject(error));
  });
}


function archiveTreeDigest(path) {
  const digest = createHash("sha256");
  const visit = (relative) => {
    const target = relative ? join(path, relative) : path;
    const metadata = lstatSync(target);
    if (metadata.isSymbolicLink()) throw new Error("indexer generation archive contains a symbolic link");
    if (metadata.isDirectory()) {
      digest.update(`directory\0${relative}\0`);
      for (const entry of readdirSync(target).sort()) visit(relative ? join(relative, entry) : entry);
      return;
    }
    if (!metadata.isFile()) throw new Error("indexer generation archive contains an unsupported filesystem entry");
    const bytes = readFileSync(target);
    digest.update(`file\0${relative}\0${bytes.length}\0`);
    digest.update(bytes);
  };
  visit("");
  return digest.digest("hex");
}


function generationId(checkpoint, archiveSha256) {
  const digest = createHash("sha256")
    .update(`${stableStringify(checkpoint)}\0${archiveSha256}`)
    .digest("hex");
  return `${String(checkpoint.range.toBlock).padStart(16, "0")}-${digest}`;
}


function syncDirectory(path) {
  const descriptor = openSync(path, "r");
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}


function readCurrentGeneration(root, validator) {
  const pointer = join(root, "current.json");
  if (!existsSync(pointer)) return null;
  const current = readStrictJsonFileSync(pointer, CHECKPOINT_LIMITS);
  if (stableStringify(Object.keys(current).sort()) !== stableStringify([
    "archive_path", "checkpoint_path", "generation_id", "schema_version",
  ])
      || current.schema_version !== "p42-indexer-generation-pointer/v1"
      || basename(current.generation_id) !== current.generation_id
      || current.checkpoint_path !== `generations/${current.generation_id}/checkpoint.json`
      || current.archive_path !== `generations/${current.generation_id}/archive`) {
    throw new Error("invalid accepted indexer generation pointer");
  }
  const path = join(root, "generations", current.generation_id);
  const checkpoint = validatePublicationCheckpoint(
    readStrictJsonFileSync(join(path, "checkpoint.json"), CHECKPOINT_LIMITS), validator,
  );
  if (!/^\d{16}-[0-9a-f]{64}$/.test(current.generation_id)
      || !current.generation_id.startsWith(`${String(checkpoint.range.toBlock).padStart(16, "0")}-`)) {
    throw new Error("accepted indexer generation id does not bind its checkpoint height");
  }
  try {
    const validated = validateGenerationDirectory(path, current.generation_id, validator);
    return { pointer: current, checkpoint, metadata: validated.metadata, integrityError: null };
  } catch (error) {
    return { pointer: current, checkpoint, metadata: null, integrityError: error };
  }
}


function validateGenerationDirectory(path, id, validator) {
  const metadata = readStrictJsonFileSync(join(path, "generation.json"), CHECKPOINT_LIMITS);
  const checkpointPath = join(path, "checkpoint.json");
  const checkpointBytes = readFileSync(checkpointPath);
  const checkpoint = validatePublicationCheckpoint(
    readStrictJsonFileSync(checkpointPath, CHECKPOINT_LIMITS), validator,
  );
  const archiveSha256 = archiveTreeDigest(join(path, "archive"));
  if (stableStringify(Object.keys(metadata).sort()) !== stableStringify([
    "archive_sha256", "checkpoint_sha256", "generation_id", "previous_generation_id", "schema_version",
  ])
      || metadata.schema_version !== "p42-indexer-generation/v2"
      || metadata.generation_id !== id
      || (metadata.previous_generation_id !== null
        && (typeof metadata.previous_generation_id !== "string"
          || basename(metadata.previous_generation_id) !== metadata.previous_generation_id))
      || metadata.checkpoint_sha256 !== createHash("sha256").update(checkpointBytes).digest("hex")
      || metadata.archive_sha256 !== archiveSha256
      || generationId(checkpoint, archiveSha256) !== id
      || !lstatSync(join(path, "archive")).isDirectory()
      || lstatSync(join(path, "archive")).isSymbolicLink()) {
    throw new Error("indexer generation metadata or archive binding is invalid");
  }
  return { checkpoint, metadata };
}


function assertMatchingGenerationTrees(left, right, relative = "") {
  const leftPath = relative ? join(left, relative) : left;
  const rightPath = relative ? join(right, relative) : right;
  const leftStat = lstatSync(leftPath);
  const rightStat = lstatSync(rightPath);
  if (leftStat.isSymbolicLink() || rightStat.isSymbolicLink()
      || leftStat.isDirectory() !== rightStat.isDirectory()
      || leftStat.isFile() !== rightStat.isFile()) {
    throw new Error("recovered indexer generation has mismatched file types");
  }
  if (leftStat.isFile()) {
    if (!readFileSync(leftPath).equals(readFileSync(rightPath))) {
      throw new Error("recovered indexer generation does not match regenerated bytes");
    }
    return;
  }
  if (!leftStat.isDirectory()) throw new Error("recovered indexer generation contains unsupported filesystem entries");
  const leftEntries = readdirSync(leftPath).sort();
  const rightEntries = readdirSync(rightPath).sort();
  if (stableStringify(leftEntries) !== stableStringify(rightEntries)) {
    throw new Error("recovered indexer generation does not match regenerated files");
  }
  for (const entry of leftEntries) assertMatchingGenerationTrees(left, right, relative ? join(relative, entry) : entry);
}


export function publishGenerationSync({
  publicationRoot, stagingPath, validator = validateMultiBoardCheckpoint, ownership = null,
} = {}) {
  ownership?.assertOwned?.();
  const root = resolve(publicationRoot);
  const stage = resolve(stagingPath);
  const candidatePath = join(stage, "checkpoint.json");
  mkdirSync(join(root, "generations"), { recursive: true, mode: 0o700 });
  mkdirSync(join(root, "quarantine"), { recursive: true, mode: 0o700 });
  const current = readCurrentGeneration(root, validator);
  let candidate;
  let decision;
  try {
    candidate = validatePublicationCheckpoint(readStrictJsonFileSync(candidatePath, CHECKPOINT_LIMITS), validator);
    if (!statSync(join(stage, "archive")).isDirectory()) throw new Error("indexer generation archive is absent");
    decision = monotonicCheckpointDecision(candidate, current?.checkpoint ?? null);
  } catch (error) {
    const rejected = join(root, "quarantine", `${Date.now()}-${randomBytes(8).toString("hex")}`);
    writeFileSync(join(stage, "quarantine.json"), `${stableStringify({
      schema_version: "p42-indexer-quarantine/v1", reason: sanitizedError(error),
      rejected_at_utc: iso(Date.now()), accepted_generation_id: current?.pointer.generation_id ?? null,
    })}\n`, { mode: 0o600 });
    renameSync(stage, rejected);
    syncDirectory(join(root, "quarantine"));
    throw error;
  }
  const archiveSha256 = archiveTreeDigest(join(stage, "archive"));
  const id = generationId(candidate, archiveSha256);
  const destination = join(root, "generations", id);
  const exactRetry = decision.decision === "unchanged" && current.pointer.generation_id === id;
  writeFileSync(join(stage, "generation.json"), `${stableStringify({
    schema_version: "p42-indexer-generation/v2", generation_id: id,
    archive_sha256: archiveSha256,
    checkpoint_sha256: createHash("sha256").update(readFileSync(candidatePath)).digest("hex"),
    previous_generation_id: exactRetry
      ? current.metadata?.previous_generation_id ?? null : current?.pointer.generation_id ?? null,
  })}\n`, { mode: 0o600 });
  validateGenerationDirectory(stage, id, validator);
  if (exactRetry && current.integrityError === null) {
    assertMatchingGenerationTrees(destination, stage);
    rmSync(stage, { recursive: true, force: true });
    return { ...decision, checkpoint: candidate, generationId: id };
  }
  if (existsSync(destination)) {
    if (exactRetry) {
      const rejected = join(root, "quarantine", `${Date.now()}-${randomBytes(8).toString("hex")}`);
      renameSync(destination, rejected);
      try {
        renameSync(stage, destination);
      } catch (error) {
        renameSync(rejected, destination);
        throw error;
      }
      rmSync(rejected, { recursive: true, force: true });
      syncDirectory(join(root, "generations"));
      syncDirectory(join(root, "quarantine"));
    } else {
      const recovered = validateGenerationDirectory(destination, id, validator);
      if (stableStringify(recovered.checkpoint) !== stableStringify(candidate)) {
        throw new Error("recovered indexer generation checkpoint does not match regenerated candidate");
      }
      assertMatchingGenerationTrees(destination, stage);
      rmSync(stage, { recursive: true, force: true });
    }
  } else {
    renameSync(stage, destination);
    syncDirectory(join(root, "generations"));
  }
  const pointer = { schema_version: "p42-indexer-generation-pointer/v1", generation_id: id,
    checkpoint_path: `generations/${id}/checkpoint.json`, archive_path: `generations/${id}/archive` };
  ownership?.assertOwned?.();
  writeFileAtomicSync(join(root, "current.json"), `${stableStringify(pointer)}\n`);
  if (decision.decision === "unchanged" && current.pointer.generation_id !== id) {
    rmSync(join(root, "generations", current.pointer.generation_id), { recursive: true, force: true });
    syncDirectory(join(root, "generations"));
  }
  return { ...decision, checkpoint: candidate, generationId: id };
}


export function buildIndexerServiceHealth({
  serviceId,
  startedAtMs,
  observedAtMs,
  lastAttemptAtMs = null,
  lastSuccessAtMs = null,
  consecutiveFailures = 0,
  maxStaleSeconds,
  checkpoint = null,
  latestError = null,
  headLastAdvancedAtMs = lastSuccessAtMs,
  publicationLastSuccessAtMs = lastSuccessAtMs,
  rpcLastSuccessAtMs = lastSuccessAtMs,
  rpcCurrentFailure = false,
  maxHeadStallSeconds = maxStaleSeconds,
}) {
  requirePositiveInteger(maxStaleSeconds, "maxStaleSeconds");
  const ageSeconds = lastSuccessAtMs === null
    ? Math.max(0, Math.floor((observedAtMs - startedAtMs) / 1000))
    : Math.max(0, Math.floor((observedAtMs - lastSuccessAtMs) / 1000));
  let status = "starting";
  if (lastSuccessAtMs !== null) status = consecutiveFailures === 0 ? "healthy" : "degraded";
  else if (consecutiveFailures > 0) status = "degraded";
  if (ageSeconds > maxStaleSeconds) status = "stale";
  const headLagSeconds = headLastAdvancedAtMs === null ? ageSeconds
    : Math.max(0, Math.floor((observedAtMs - headLastAdvancedAtMs) / 1000));
  const checkpointAgeSeconds = checkpoint?.range?.toBlockTimestamp
    ? Math.max(0, Math.floor(observedAtMs / 1000) - checkpoint.range.toBlockTimestamp) : null;
  const frozen = lastSuccessAtMs !== null && headLagSeconds > maxHeadStallSeconds;
  if (frozen && status === "healthy") status = "degraded";
  if (checkpointAgeSeconds !== null && checkpointAgeSeconds > maxStaleSeconds) status = "stale";
  return {
    schema: SERVICE_SCHEMA,
    service_id: serviceId,
    status,
    observed_at_utc: iso(observedAtMs),
    started_at_utc: iso(startedAtMs),
    last_attempt_at_utc: lastAttemptAtMs === null ? null : iso(lastAttemptAtMs),
    last_success_at_utc: lastSuccessAtMs === null ? null : iso(lastSuccessAtMs),
    last_success_age_seconds: ageSeconds,
    max_stale_seconds: maxStaleSeconds,
    consecutive_failures: consecutiveFailures,
    checkpoint: checkpointSummary(checkpoint),
    latest_error: latestError,
    components: {
      process: { status: consecutiveFailures >= 5 ? "failed" : "running", consecutive_failures: consecutiveFailures },
      rpc: { status: rpcLastSuccessAtMs === null || rpcCurrentFailure || frozen ? "degraded" : "healthy", frozen: frozen,
        current_failure: rpcCurrentFailure,
        last_success_at_utc: rpcLastSuccessAtMs === null ? null : iso(rpcLastSuccessAtMs) },
      publication: { status: publicationLastSuccessAtMs === null ? "starting" : "healthy",
        last_success_at_utc: publicationLastSuccessAtMs === null ? null : iso(publicationLastSuccessAtMs) },
      finalized_head: { status: frozen ? "degraded" : "healthy", advancement_lag_seconds: headLagSeconds },
      checkpoint: { status: checkpointAgeSeconds !== null && checkpointAgeSeconds > maxStaleSeconds ? "stale" : "healthy",
        age_seconds: checkpointAgeSeconds, publication_age_seconds: ageSeconds },
    },
  };
}


export async function runIndexerService(options, dependencies = {}) {
  const {
    serviceId = "p42-indexer",
    candidatePath,
    outputPath,
    publicationRoot,
    healthPath,
    intervalMs = 30_000,
    maxStaleSeconds = 300,
    maxConsecutiveFailures = 5,
    once = false,
    indexerOptions,
  } = options ?? {};
  requirePositiveInteger(intervalMs, "intervalMs");
  requirePositiveInteger(maxStaleSeconds, "maxStaleSeconds");
  requirePositiveInteger(maxConsecutiveFailures, "maxConsecutiveFailures");
  if ((!publicationRoot && (!candidatePath || !outputPath)) || !healthPath || !indexerOptions) {
    throw new Error("indexer service requires publicationRoot (or legacy candidate/output), healthPath, and indexerOptions");
  }
  const resolvedRoot = publicationRoot ? resolve(publicationRoot) : null;
  const resolvedCandidate = candidatePath ? resolve(candidatePath) : null;
  const resolvedOutput = outputPath ? resolve(outputPath) : null;
  const resolvedHealth = resolve(healthPath);
  if (!resolvedRoot && new Set([resolvedCandidate, resolvedOutput, resolvedHealth]).size !== 3) {
    throw new Error("indexer service candidate, output, and health paths must be distinct");
  }
  const runIndexerImpl = dependencies.runIndexerImpl ?? runIndexer;
  const publishImpl = dependencies.publishImpl ?? publishMonotonicCheckpointSync;
  const writeHealthImpl = dependencies.writeHealthImpl
    ?? ((health) => writeFileAtomicSync(resolvedHealth, `${stableStringify(health)}\n`));
  const nowImpl = dependencies.nowImpl ?? Date.now;
  const sleepImpl = dependencies.sleepImpl ?? ((milliseconds) => new Promise((done) => setTimeout(done, milliseconds)));
  const startedAtMs = nowImpl();
  let lastAttemptAtMs = null;
  let lastSuccessAtMs = null;
  let consecutiveFailures = 0;
  let checkpoint = null;
  let latestError = null;
  let lastHead = null;
  let headLastAdvancedAtMs = null;
  let rpcLastSuccessAtMs = null;
  let publicationLastSuccessAtMs = null;
  let rpcCurrentFailure = false;

  const publishHealth = () => writeHealthImpl(buildIndexerServiceHealth({
    serviceId,
    startedAtMs,
    observedAtMs: nowImpl(),
    lastAttemptAtMs,
    lastSuccessAtMs,
    consecutiveFailures,
    maxStaleSeconds,
    checkpoint,
    latestError,
    headLastAdvancedAtMs,
    rpcLastSuccessAtMs,
    rpcCurrentFailure,
    publicationLastSuccessAtMs,
  }));
  publishHealth();

  for (;;) {
    lastAttemptAtMs = nowImpl();
    rpcCurrentFailure = true;
    const releaseLock = resolvedRoot
      ? await (dependencies.acquireLockImpl ?? acquireIndexerSingletonLock)(join(resolvedRoot, "publisher.lock"))
      : async () => {};
    try {
      {
        let cycleCandidate = resolvedCandidate;
        let stage = null;
        if (resolvedRoot) {
          mkdirSync(join(resolvedRoot, "staging"), { recursive: true, mode: 0o700 });
          stage = join(resolvedRoot, "staging", `${process.pid}-${randomBytes(8).toString("hex")}`);
          mkdirSync(join(stage, "archive"), { recursive: true, mode: 0o700 });
          cycleCandidate = join(stage, "checkpoint.json");
        }
        const generated = await runIndexerImpl({ ...indexerOptions, outPath: cycleCandidate,
          ...(resolvedRoot ? { archivePath: join(stage, "archive") } : {}) });
        if (generated.reconstruction?.complete !== true || generated.reconstruction?.ok !== true) {
          throw new Error("indexer cycle reconstruction was incomplete or failed");
        }
        releaseLock.assertOwned?.();
        rpcLastSuccessAtMs = nowImpl();
        rpcCurrentFailure = false;
        if (lastHead === null || generated.range.toBlock > lastHead) headLastAdvancedAtMs = rpcLastSuccessAtMs;
        lastHead = generated.range.toBlock;
        const publication = resolvedRoot
          ? (dependencies.publishGenerationImpl ?? publishGenerationSync)({
            publicationRoot: resolvedRoot, stagingPath: stage, ownership: releaseLock,
          })
          : publishImpl({ candidatePath: resolvedCandidate, outputPath: resolvedOutput });
        checkpoint = publication.checkpoint;
        lastSuccessAtMs = nowImpl();
        publicationLastSuccessAtMs = lastSuccessAtMs;
        consecutiveFailures = 0;
        latestError = null;
        publishHealth();
      }
    } catch (error) {
      consecutiveFailures += 1;
      latestError = { message: sanitizedError(error), failed_at_utc: iso(nowImpl()) };
      publishHealth();
      if (once || consecutiveFailures >= maxConsecutiveFailures) throw error;
    } finally {
      await releaseLock();
    }
    if (once) return checkpoint;
    await sleepImpl(intervalMs);
  }
}


function optionValues(argv, name) {
  const values = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] !== `--${name}`) continue;
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`--${name} requires a value`);
    values.push(value);
  }
  return values;
}


function option(argv, name, fallback = null, { required = false } = {}) {
  const values = optionValues(argv, name);
  if (values.length > 1) throw new Error(`--${name} may be provided only once`);
  if (required && values.length !== 1) throw new Error(`--${name} is required`);
  return values[0] ?? fallback;
}


export async function cli(argv = process.argv, env = process.env) {
  const manifestPath = option(argv, "manifest", null, { required: true });
  const publicationRoot = option(argv, "publication-root", null, { required: true });
  const healthPath = option(argv, "health", null, { required: true });
  const rpcUrlFile = option(argv, "rpc-url-file", null, { required: true });
  const secondaryRpcUrlFile = option(argv, "secondary-rpc-url-file");
  const transcriptConfig = configureIndexerTranscripts(argv, env);
  const activationNames = [
    "activation-plan", "activation-completion", "activation-authorization", "activation-trust-registry",
    "activation-artifact-root", "activation-python", "activation-repo-root", "activation-rpc-registry",
    "activation-rpc-registry-trusted-root",
  ];
  const activation = Object.fromEntries(activationNames.map((name) => [name, option(argv, name)]));
  const indexerOptions = {
    manifestPath,
    rpcUrl: readCredentialUrl(rpcUrlFile, "indexer primary RPC URL credential"),
    transcriptEndpoints: transcriptConfig.endpoints,
    transcriptFetchClient: transcriptConfig.fetchClient,
    activationPlanPath: activation["activation-plan"],
    activationCompletionPath: activation["activation-completion"],
    activationAuthorizationPath: activation["activation-authorization"],
    activationTrustRegistryPath: activation["activation-trust-registry"],
    activationArtifactRoot: activation["activation-artifact-root"],
    activationPython: activation["activation-python"],
    activationRepoRoot: activation["activation-repo-root"],
    activationRpcRegistryPath: activation["activation-rpc-registry"],
    activationRpcRegistryTrustedRoot: activation["activation-rpc-registry-trusted-root"],
    secondaryRpcUrl: secondaryRpcUrlFile
      ? readCredentialUrl(secondaryRpcUrlFile, "indexer secondary RPC URL credential")
      : null,
  };
  return runIndexerService({
    serviceId: option(argv, "service-id", "p42-indexer"),
    publicationRoot,
    healthPath,
    intervalMs: Number(option(argv, "interval-ms", "30000")),
    maxStaleSeconds: Number(option(argv, "max-stale-seconds", "300")),
    maxConsecutiveFailures: Number(option(argv, "max-consecutive-failures", "5")),
    once: argv.includes("--once"),
    indexerOptions,
  });
}


const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  cli().catch((error) => {
    console.error(`FAILED: ${sanitizedError(error)}`);
    process.exitCode = 1;
  });
}
