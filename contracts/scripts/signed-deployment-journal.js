import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, realpathSync, renameSync, rmdirSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname, join, parse, resolve, sep } from "node:path";
import { hostname } from "node:os";
import { Transaction, getCreateAddress, getCreate2Address, keccak256, zeroPadValue } from "ethers";
import { parseStrictJsonBytes } from "../../agent/strict-json.mjs";

export const SIGNED_DEPLOYMENT_JOURNAL_SCHEMA = "p42-prizes/signed-deployment-journal/v1";
const STATES = Object.freeze({ planned: 0, signed: 1, broadcast: 2, mined: 3 });
const STEP_KINDS = Object.freeze({ "direct-create": true, "factory-call-create2": true });
const MAX_JOURNAL_BYTES = 16 * 1024 * 1024;

export function normalizeTrustedRpcEndpoint(raw, label = "RPC endpoint") {
  let url;
  try { url = new URL(raw); } catch { throw new Error(`${label} must be an absolute URL`); }
  if (url.protocol !== "https:" && url.hostname !== "127.0.0.1" && url.hostname !== "localhost") throw new Error(`${label} must use https`);
  url.hash = "";
  return Object.freeze({ href: url.href, origin: url.origin.toLowerCase(), host: url.hostname.toLowerCase() });
}

export function buildTrustedRpcEvidence({ primaryUrl, secondaryUrl, primaryOperatorId, secondaryOperatorId }) {
  const operator = (value, label) => {
    const normalized = String(value ?? "").toLowerCase();
    if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(normalized)) throw new Error(`${label} must be a canonical operator identifier`);
    return normalized;
  };
  const primary = normalizeTrustedRpcEndpoint(primaryUrl, "primary RPC");
  const secondary = normalizeTrustedRpcEndpoint(secondaryUrl, "secondary RPC");
  const firstOperator = operator(primaryOperatorId, "primary RPC operator ID");
  const secondOperator = operator(secondaryOperatorId, "secondary RPC operator ID");
  if (firstOperator === secondOperator || primary.href === secondary.href || primary.origin === secondary.origin || primary.host === secondary.host) {
    throw new Error("RPCs must have distinct endpoint URLs, operator IDs, origins, and hosts");
  }
  return Object.freeze({
    primaryOperatorId: firstOperator, secondaryOperatorId: secondOperator,
    primaryOrigin: primary.origin, secondaryOrigin: secondary.origin,
    primaryHost: primary.host, secondaryHost: secondary.host,
    primaryEndpointDigest: `sha256:${createHash("sha256").update(primary.href).digest("hex")}`,
    secondaryEndpointDigest: `sha256:${createHash("sha256").update(secondary.href).digest("hex")}`,
  });
}

function canonical(value) {
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function digest(value) {
  return `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
}

function assertHex(value, bytes, label) {
  if (typeof value !== "string" || !new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(value)) {
    throw new Error(`${label} is not canonical ${bytes}-byte hex`);
  }
}

function durableWrite(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  let fd;
  try {
    fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
    for (let offset = 0; offset < bytes.length;) {
      const written = writeSync(fd, bytes, offset, bytes.length - offset, offset);
      if (written <= 0) throw new Error("signed deployment journal write made no progress");
      offset += written;
    }
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temporary, path);
    const directory = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temporary); } catch {}
    throw error;
  }
}

function durableCreate(path, value) {
  assertTrustedAncestors(path);
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  let fd;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    for (let offset = 0; offset < bytes.length;) offset += writeSync(fd, bytes, offset, bytes.length - offset, offset);
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    const directory = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    throw error;
  }
}

function assertTrustedAncestors(path) {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  let current = root;
  for (const component of dirname(absolute).slice(root.length).split(sep).filter(Boolean)) {
    current = resolve(current, component);
    const metadata = lstatSync(current);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("signed deployment journal ancestor is not a real directory");
    if (typeof process.getuid === "function" && metadata.uid !== process.getuid() && metadata.uid !== 0) throw new Error("signed deployment journal ancestor owner mismatch");
    if ((metadata.mode & 0o002) !== 0 && current !== "/private/tmp" && current !== "/tmp") throw new Error("signed deployment journal ancestor is world-writable");
  }
}

function readJournal(path) {
  assertTrustedAncestors(path);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let record;
  try {
    const before = lstatSync(path);
    const metadata = fstatSync(fd);
    if (!metadata.isFile() || metadata.nlink !== 1 || before.ino !== metadata.ino || before.dev !== metadata.dev) throw new Error("signed deployment journal inode changed during open");
    if ((metadata.mode & 0o777) !== 0o600) throw new Error("signed deployment journal must have mode 0600");
    if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) throw new Error("signed deployment journal owner mismatch");
    if (metadata.size < 2 || metadata.size > MAX_JOURNAL_BYTES) throw new Error("signed deployment journal size is invalid");
    const bytes = Buffer.alloc(metadata.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) throw new Error("signed deployment journal was truncated during read");
      offset += count;
    }
    const after = lstatSync(path);
    if (after.ino !== metadata.ino || after.dev !== metadata.dev || after.size !== metadata.size) throw new Error("signed deployment journal changed during read");
    record = parseStrictJsonBytes(bytes, { maxBytes: MAX_JOURNAL_BYTES, maxDepth: 64, trailingNewline: "require" });
  } finally { closeSync(fd); }
  assertJournal(record);
  return record;
}

function immutableView(record) {
  return {
    schema: record.schema, identityDigest: record.identityDigest, network: record.network,
    chainId: record.chainId, deployer: record.deployer, rpcEvidence: record.rpcEvidence, startNonce: record.startNonce,
    transactionCount: record.transactionCount, endNonceExclusive: record.endNonceExclusive,
    steps: record.steps.map(({ id, name, kind, nonce, address, constructorArgsHash, expectedInitCodeHash, expectedTo, expectedCalldataHash, expectedValue, factoryAddress, salt, configurationHash, configurationReadCalldata, deploymentEventTopic }) => ({
      id, name, kind, nonce, address, constructorArgsHash, expectedInitCodeHash, expectedTo, expectedCalldataHash,
      expectedValue, factoryAddress, salt, configurationHash, configurationReadCalldata, deploymentEventTopic,
    })),
  };
}

function assertJournal(record) {
  if (record?.schema !== SIGNED_DEPLOYMENT_JOURNAL_SCHEMA || !Array.isArray(record.steps) || record.steps.length < 1) throw new Error("malformed signed deployment journal");
  if (!Number.isSafeInteger(record.chainId) || !Number.isSafeInteger(record.startNonce) || record.startNonce < 0) throw new Error("malformed signed deployment journal identity");
  if (record.transactionCount !== record.steps.length || record.endNonceExclusive !== record.startNonce + record.steps.length) throw new Error("signed deployment nonce range is not exact");
  assertHex(record.deployer, 20, "deployer");
  if (
    !record.rpcEvidence || record.rpcEvidence.primaryOperatorId === record.rpcEvidence.secondaryOperatorId ||
    record.rpcEvidence.primaryOrigin === record.rpcEvidence.secondaryOrigin ||
    record.rpcEvidence.primaryHost === record.rpcEvidence.secondaryHost ||
    !/^sha256:[0-9a-f]{64}$/.test(record.rpcEvidence.primaryEndpointDigest ?? "") ||
    !/^sha256:[0-9a-f]{64}$/.test(record.rpcEvidence.secondaryEndpointDigest ?? "")
  ) throw new Error("deployment RPC evidence identities are not independent and immutable");
  for (const [index, step] of record.steps.entries()) {
    if (step.nonce !== record.startNonce + index || step.id !== `${index}:${step.name}`) throw new Error("signed deployment step identity or nonce drift");
    if (!(step.kind in STEP_KINDS)) throw new Error("signed deployment step kind is not closed");
    assertHex(step.address, 20, "deployment address");
    assertHex(step.constructorArgsHash, 32, "constructor args hash");
    assertHex(step.expectedInitCodeHash, 32, "expected initcode hash");
    assertHex(step.expectedCalldataHash, 32, "expected calldata hash");
    if (!/^(0|[1-9][0-9]*)$/.test(step.expectedValue ?? "")) throw new Error("deployment plan value is not canonical");
    if (step.kind === "direct-create") {
      if (step.expectedTo !== null || step.factoryAddress !== null || step.salt !== null || step.configurationHash !== null || step.configurationReadCalldata !== null || step.deploymentEventTopic !== null || step.expectedCalldataHash.toLowerCase() !== step.expectedInitCodeHash.toLowerCase()) throw new Error("direct CREATE deployment kind drift");
      if (getCreateAddress({ from: record.deployer, nonce: step.nonce }).toLowerCase() !== step.address.toLowerCase()) throw new Error("direct CREATE predicted address drift");
    } else {
      assertHex(step.expectedTo, 20, "factory transaction target");
      assertHex(step.factoryAddress, 20, "pinned factory");
      assertHex(step.salt, 32, "CREATE2 salt");
      assertHex(step.configurationHash, 32, "CREATE2 configuration hash");
      if (typeof step.configurationReadCalldata !== "string" || !/^0x[0-9a-fA-F]{8,}$/.test(step.configurationReadCalldata) || step.configurationReadCalldata.length % 2 !== 0) throw new Error("CREATE2 configuration read calldata is not canonical");
      assertHex(step.deploymentEventTopic, 32, "factory deployment event topic");
      if (step.expectedTo.toLowerCase() !== step.factoryAddress.toLowerCase()) throw new Error("factory transaction target differs from pinned factory");
      if (getCreate2Address(step.factoryAddress, step.salt, step.expectedInitCodeHash).toLowerCase() !== step.address.toLowerCase()) throw new Error("CREATE2 predicted address drift");
    }
    if (!(step.state in STATES)) throw new Error("invalid signed deployment state");
    if (STATES[step.state] >= STATES.signed) {
      if (typeof step.rawTransaction !== "string" || !/^0x[0-9a-f]+$/i.test(step.rawTransaction)) throw new Error("signed step lacks raw transaction bytes");
      assertHex(step.expectedHash, 32, "expected transaction hash");
      assertHex(step.calldataHash, 32, "calldata hash");
      if (step.expectedHash.toLowerCase() !== keccak256(step.rawTransaction).toLowerCase()) throw new Error("signed transaction raw/hash substitution detected");
      const transaction = Transaction.from(step.rawTransaction);
      if (
        transaction.from?.toLowerCase() !== record.deployer.toLowerCase() || transaction.chainId !== BigInt(record.chainId) ||
        transaction.nonce !== step.nonce || (transaction.to?.toLowerCase() ?? null) !== (step.expectedTo?.toLowerCase() ?? null) ||
        transaction.value.toString() !== step.expectedValue || keccak256(transaction.data).toLowerCase() !== step.expectedCalldataHash.toLowerCase()
      ) throw new Error("signed deployment payload identity drift");
      const payload = {
        rawHash: step.expectedHash.toLowerCase(), signer: transaction.from.toLowerCase(), chainId: transaction.chainId.toString(),
        nonce: transaction.nonce, to: transaction.to?.toLowerCase() ?? null, value: transaction.value.toString(),
        calldataHash: step.calldataHash.toLowerCase(), address: step.address.toLowerCase(), kind: step.kind,
      };
      if (step.signedPayloadDigest !== digest(payload)) throw new Error("signed deployment payload digest mismatch");
    }
    if (step.state === "mined" && (!Number.isSafeInteger(step.blockNumber) || step.blockNumber < 0)) throw new Error("mined step lacks block number");
  }
  if (record.planDigest !== digest(immutableView(record))) throw new Error("signed deployment plan digest mismatch");
  return record;
}

export function signedDeploymentJournalPath(manifestPath) {
  const absolute = resolve(manifestPath);
  return join(realpathSync(dirname(absolute)), `${basename(absolute)}.signed-transactions.json`);
}

export function buildDeploymentNoncePlan(ethers, { identityDigest, network, chainId, deployer, rpcEvidence, startNonce, steps }) {
  if (!Array.isArray(steps) || steps.length < 1) throw new Error("deployment transaction plan must not be empty");
  const normalized = steps.map((step, index) => {
    const kind = step.kind ?? "direct-create";
    if (!(kind in STEP_KINDS)) throw new Error("deployment transaction plan contains an unknown step kind");
    const nonce = startNonce + index;
    const expectedInitCodeHash = keccak256(step.expectedInitCode);
    const factoryAddress = kind === "factory-call-create2" ? ethers.getAddress(step.factoryAddress) : null;
    const salt = kind === "factory-call-create2" ? step.salt : null;
    const address = kind === "direct-create"
      ? ethers.getCreateAddress({ from: deployer, nonce })
      : ethers.getCreate2Address(factoryAddress, salt, expectedInitCodeHash);
    const expectedCalldata = kind === "direct-create" ? step.expectedInitCode : step.expectedCalldata;
    return {
      id: `${index}:${step.name}`, name: step.name, kind, nonce, address,
      constructorArgsHash: step.constructorArgsHash, expectedInitCodeHash,
      expectedTo: factoryAddress, expectedCalldataHash: keccak256(expectedCalldata),
      expectedValue: String(step.expectedValue ?? 0), factoryAddress, salt,
      configurationHash: kind === "factory-call-create2" ? step.configurationHash : null,
      configurationReadCalldata: kind === "factory-call-create2" ? step.configurationReadCalldata : null,
      deploymentEventTopic: kind === "factory-call-create2" ? step.deploymentEventTopic : null,
      state: "planned", rawTransaction: null, expectedHash: null, blockNumber: null,
    };
  });
  const record = {
    schema: SIGNED_DEPLOYMENT_JOURNAL_SCHEMA, identityDigest, network, chainId, deployer, rpcEvidence,
    startNonce, transactionCount: normalized.length, endNonceExclusive: startNonce + normalized.length,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), generation: 0, steps: normalized,
  };
  record.planDigest = digest(immutableView(record));
  return assertJournal(record);
}

export function buildExecutableDeploymentNoncePlan(ethers, metadata, executableSteps, executableAddresses = null) {
  const canonicalSteps = executableSteps.map((step) => {
    const direct = step.kind === "direct-create";
    const expectedKeys = direct ? ["data"] : ["data", "to", "value"];
    if (!step.unsigned || Object.keys(step.unsigned).sort().join(",") !== expectedKeys.join(",")) {
      throw new Error(`${step.id} unsigned deployment transaction shape is not canonical`);
    }
    if (direct) {
      if (step.unsigned.data !== step.expectedInitCode) throw new Error(`${step.id} direct deployment bytes differ from expected initcode`);
    } else if (
      step.unsigned.data !== step.expectedCalldata
      || String(step.unsigned.to).toLowerCase() !== String(step.factoryAddress).toLowerCase()
      || BigInt(step.unsigned.value) !== 0n
    ) {
      throw new Error(`${step.id} factory deployment transaction differs from expected calldata`);
    }
    return {
      name: step.id,
      kind: step.kind,
      constructorArgsHash: step.constructorArgsHash,
      expectedInitCode: step.expectedInitCode,
      ...(step.kind === "factory-call-create2" ? {
        factoryAddress: step.factoryAddress,
        salt: step.salt,
        configurationHash: step.configurationHash,
        configurationReadCalldata: step.configurationReadCalldata,
        deploymentEventTopic: step.deploymentEventTopic,
        expectedCalldata: step.expectedCalldata,
        expectedValue: 0,
      } : {}),
    };
  });
  const plan = buildDeploymentNoncePlan(ethers, {
    ...metadata,
    steps: canonicalSteps,
  });
  if (executableAddresses !== null) {
    for (const [index, step] of executableSteps.entries()) {
      if (String(executableAddresses[step.addressKey]).toLowerCase() !== plan.steps[index].address.toLowerCase()) {
        throw new Error(`${step.id} executable address differs from its canonical deployment payload`);
      }
    }
  }
  return plan;
}

export function reserveDeploymentNoncePlan(path, expected) {
  try {
    const existing = readJournal(path);
    if (existing.planDigest !== expected.planDigest || canonical(immutableView(existing)) !== canonical(immutableView(expected))) {
      throw new Error("existing signed deployment journal does not match chain/account/config/nonce plan");
    }
    return existing;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  try { durableCreate(path, expected); }
  catch (error) {
    if (error?.code !== "EEXIST") throw error;
    const winner = readJournal(path);
    if (winner.planDigest !== expected.planDigest || canonical(immutableView(winner)) !== canonical(immutableView(expected))) throw new Error("concurrent signed deployment reservation conflicts with expected plan");
  }
  return readJournal(path);
}

function transition(path, expectedPlanDigest, index, nextState, patch) {
  const record = readJournal(path);
  if (record.planDigest !== expectedPlanDigest) throw new Error("signed deployment plan changed during execution");
  const step = record.steps[index];
  if (!step || STATES[nextState] < STATES[step.state]) throw new Error("signed deployment journal transition cannot regress");
  if (STATES[nextState] > STATES[step.state] + 1) throw new Error("signed deployment journal transition cannot skip a state");
  if (STATES[nextState] === STATES[step.state]) {
    for (const [key, value] of Object.entries(patch)) if (canonical(step[key]) !== canonical(value)) throw new Error("signed deployment journal transition conflicts with durable state");
    return record;
  }
  Object.assign(step, patch, { state: nextState });
  record.generation += 1;
  record.updatedAt = new Date().toISOString();
  assertJournal(record);
  durableWrite(path, record);
  return readJournal(path);
}

export function persistSignedDeployment(path, planDigest, index, ethers, rawTransaction) {
  const expectedHash = ethers.keccak256(rawTransaction);
  const transaction = Transaction.from(rawTransaction);
  const calldataHash = keccak256(transaction.data);
  const current = readJournal(path);
  const step = current.steps[index];
  if (calldataHash.toLowerCase() !== step.expectedCalldataHash.toLowerCase()) throw new Error("signed transaction calldata differs from immutable deployment plan");
  const signedPayloadDigest = digest({
    rawHash: expectedHash.toLowerCase(), signer: transaction.from?.toLowerCase(), chainId: transaction.chainId.toString(),
    nonce: transaction.nonce, to: transaction.to?.toLowerCase() ?? null, value: transaction.value.toString(),
    calldataHash: calldataHash.toLowerCase(), address: step.address.toLowerCase(), kind: step.kind,
  });
  return transition(path, planDigest, index, "signed", { rawTransaction, expectedHash, calldataHash, signedPayloadDigest });
}

export function recordDeploymentBroadcast(path, planDigest, index) {
  return transition(path, planDigest, index, "broadcast", {});
}

export function recordDeploymentMined(path, planDigest, index, blockNumber) {
  const current = readJournal(path);
  if (current.steps[index]?.state === "signed") transition(path, planDigest, index, "broadcast", {});
  return transition(path, planDigest, index, "mined", { blockNumber });
}

function bootIdentity() {
  try { return readSmallSystemFile("/proc/sys/kernel/random/boot_id"); } catch {}
  try { return execFileSync("sysctl", ["-n", "kern.boottime"], { encoding: "utf8" }).trim(); } catch {}
  throw new Error("cannot establish host boot identity for deployment lock");
}

function readSmallSystemFile(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(fd);
    if (!metadata.isFile() || metadata.size > 4096) throw new Error("invalid system identity file");
    // procfs reports zero for many virtual-file sizes. Read through the held
    // descriptor with a hard ceiling instead of trusting stat.size.
    const bytes = Buffer.alloc(4097);
    const count = readSync(fd, bytes, 0, bytes.length, null);
    if (count === 0 || count > 4096) throw new Error("invalid system identity file");
    const value = bytes.subarray(0, count).toString("utf8").trim();
    if (!value) throw new Error("invalid system identity file");
    return value;
  } finally { closeSync(fd); }
}

function processStartIdentity(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    const stat = readSmallSystemFile(`/proc/${pid}/stat`);
    const close = stat.lastIndexOf(")");
    return `linux:${stat.slice(close + 2).split(" ")[19]}`;
  } catch {}
  try {
    const value = execFileSync("ps", ["-o", "lstart=", "-p", String(pid)], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return value ? `ps:${value}` : null;
  } catch { return null; }
}

export function deploymentLockOwnerIdentity(pid = process.pid) {
  const processStartId = processStartIdentity(pid);
  if (!processStartId) throw new Error("cannot establish deployment runner process start identity");
  const identity = { hostname: hostname(), pid, bootId: bootIdentity(), processStartId };
  if (identity.hostname.length < 1 || identity.bootId.length < 4 || identity.processStartId.length < 4) {
    throw new Error("deployment runner lock identity is incomplete");
  }
  return identity;
}

function readLock(path) {
  const directoryMetadata = lstatSync(path);
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink() || (directoryMetadata.mode & 0o777) !== 0o700) throw new Error("deployment lock directory is unsafe");
  const ownerPath = join(path, "owner.json");
  const fd = openSync(ownerPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(fd);
    if (!metadata.isFile() || metadata.nlink !== 1 || metadata.size < 2 || metadata.size > 4096 || (metadata.mode & 0o777) !== 0o600) throw new Error("deployment lock metadata is unsafe");
    const bytes = Buffer.alloc(metadata.size);
    readSync(fd, bytes, 0, bytes.length, 0);
    return { owner: parseStrictJsonBytes(bytes, { maxBytes: 4096, maxDepth: 8, trailingNewline: "require" }), metadata: directoryMetadata };
  } finally { closeSync(fd); }
}

function removeQuarantinedLock(path, expectedToken, expectedMetadata) {
  const current = lstatSync(path);
  if (current.ino !== expectedMetadata.ino || current.dev !== expectedMetadata.dev || !current.isDirectory()) throw new Error("quarantined deployment lock inode mismatch");
  const { owner } = readLock(path);
  if (owner.token !== expectedToken) throw new Error("quarantined deployment lock ownership token mismatch");
  unlinkSync(join(path, "owner.json"));
  rmdirSync(path);
}

function prepareLockCandidate(lockPath, owner) {
  const candidate = `${lockPath}.candidate-${owner.token}`;
  const ownerPath = join(candidate, "owner.json");
  mkdirSync(candidate, { mode: 0o700 });
  let fd;
  try {
    fd = openSync(ownerPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const bytes = Buffer.from(`${JSON.stringify(owner)}\n`);
    writeSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    const candidateFd = openSync(candidate, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(candidateFd); } finally { closeSync(candidateFd); }
    return candidate;
  } catch (error) {
    if (fd !== undefined) {
      try { closeSync(fd); } catch {}
    }
    const cleanupErrors = [];
    try { unlinkSync(ownerPath); } catch (cleanupError) { if (cleanupError?.code !== "ENOENT") cleanupErrors.push(cleanupError); }
    try { rmdirSync(candidate); } catch (cleanupError) { if (cleanupError?.code !== "ENOENT") cleanupErrors.push(cleanupError); }
    if (cleanupErrors.length > 0) {
      throw new AggregateError([error, ...cleanupErrors], "deployment lock candidate creation and cleanup both failed");
    }
    throw error;
  }
}

function discardOwnedCandidate(candidate, token) {
  try {
    const { owner, metadata } = readLock(candidate);
    if (owner.token !== token) throw new Error("deployment lock candidate ownership mismatch");
    removeQuarantinedLock(candidate, token, metadata);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    try { rmdirSync(candidate); } catch (cleanupError) { if (cleanupError?.code !== "ENOENT") throw cleanupError; }
  }
}

export async function withDurableJournalLock(journalPath, operation, hooks = {}) {
  const lockPath = `${journalPath}.lock`;
  assertTrustedAncestors(lockPath);
  const owner = { ...deploymentLockOwnerIdentity(), createdAt: new Date().toISOString(), token: randomUUID() };
  const candidate = prepareLockCandidate(lockPath, owner);
  if (hooks.afterCandidateDurable) await hooks.afterCandidateDurable(candidate);
  try {
    try { mkdirSync(lockPath, { mode: 0o700 }); }
    catch (error) {
      if (error?.code === "EEXIST") {
        try { readLock(lockPath); }
        catch (readError) {
          if (readError?.code === "ENOENT") throw new Error("incomplete live deployment lock requires explicit operator recovery");
          throw readError;
        }
        throw new Error("another signed deployment runner may hold the reconciliation lock; explicit recovery is required if it was abandoned");
      }
      throw error;
    }
    renameSync(join(candidate, "owner.json"), join(lockPath, "owner.json"));
    const lockDirectory = openSync(lockPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(lockDirectory); } finally { closeSync(lockDirectory); }
    rmdirSync(candidate);
    const directory = openSync(dirname(lockPath), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    discardOwnedCandidate(candidate, owner.token);
    throw error;
  }
  try { return await operation(); }
  finally {
    const { owner: currentOwner, metadata } = readLock(lockPath);
    if (currentOwner.token !== owner.token) throw new Error("deployment lock ownership changed before release");
    const current = lstatSync(lockPath);
    if (current.ino !== metadata.ino || current.dev !== metadata.dev) throw new Error("deployment lock inode changed before release");
    removeQuarantinedLock(lockPath, owner.token, metadata);
    const directory = openSync(dirname(lockPath), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { fsyncSync(directory); } finally { closeSync(directory); }
  }
}

function canonicalReceiptTransactionHash(receipt, label) {
  const candidates = [receipt.hash, receipt.transactionHash].filter((value) => value !== undefined && value !== null);
  if (candidates.length === 0 || candidates.some((value) => typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value))) {
    throw new Error(`${label} receipt transaction hash is missing or malformed`);
  }
  const normalized = candidates.map((value) => value.toLowerCase());
  if (normalized.some((value) => value !== normalized[0])) throw new Error(`${label} receipt transaction hash aliases disagree`);
  return normalized[0];
}

async function canonicalReceipt(provider, step, deployer, receipt, label, blockByNumber = false) {
  const receiptAddress = receipt.contractAddress?.toLowerCase() ?? null;
  if (canonicalReceiptTransactionHash(receipt, label) !== step.expectedHash.toLowerCase() || !receipt.blockHash ||
      (step.kind === "direct-create" ? receiptAddress !== step.address.toLowerCase() : receiptAddress !== null)) throw new Error(`${label} receipt identity mismatch`);
  const transaction = await provider.getTransaction(step.expectedHash);
  if (!transaction || transaction.hash.toLowerCase() !== step.expectedHash.toLowerCase() || Number(transaction.nonce) !== step.nonce || transaction.from.toLowerCase() !== deployer.toLowerCase() ||
      (transaction.to?.toLowerCase() ?? null) !== (step.expectedTo?.toLowerCase() ?? null) || keccak256(transaction.data).toLowerCase() !== step.expectedCalldataHash.toLowerCase() || BigInt(transaction.value ?? 0).toString() !== step.expectedValue) {
    throw new Error(`${label} mined transaction identity mismatch`);
  }
  if (step.kind === "factory-call-create2") {
    const addressTopic = zeroPadValue(step.address, 32).toLowerCase();
    const matching = (receipt.logs ?? []).filter((log) => log.address?.toLowerCase() === step.factoryAddress.toLowerCase()
      && log.topics?.length === 3 && log.topics[0]?.toLowerCase() === step.deploymentEventTopic.toLowerCase()
      && log.topics[1]?.toLowerCase() === addressTopic && log.topics[2]?.toLowerCase() === step.salt.toLowerCase()
      && (log.data ?? "0x") === "0x");
    if (matching.length !== 1) throw new Error(`${label} receipt lacks the exact factory deployment event`);
    const code = await provider.getCode(step.address, Number(receipt.blockNumber));
    if (code === "0x") throw new Error(`${label} receipt lacks runtime at the predicted CREATE2 address`);
    const configuration = await provider.call({ to: step.factoryAddress, data: step.configurationReadCalldata }, Number(receipt.blockNumber));
    const expectedConfiguration = zeroPadValue(step.configurationHash, 32).toLowerCase();
    if (typeof configuration !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(configuration) || configuration.toLowerCase() !== expectedConfiguration) {
      throw new Error(`${label} factory configuration hash mismatch at the receipt block`);
    }
  }
  const block = await provider.getBlock(blockByNumber ? Number(receipt.blockNumber) : receipt.blockHash);
  if (!block || block.hash?.toLowerCase() !== receipt.blockHash.toLowerCase() || Number(block.number) !== Number(receipt.blockNumber)) throw new Error(`${label} receipt block is not canonical`);
  return { transaction, block };
}

async function reconcileLocked({ provider, secondaryProvider, journalPath, planDigest, index, allowBroadcast, requiredConfirmations = 1 }) {
  let record = readJournal(journalPath);
  const pinned = lstatSync(journalPath);
  const assertPinnedJournal = () => {
    const current = lstatSync(journalPath);
    if (current.ino !== pinned.ino || current.dev !== pinned.dev || current.isSymbolicLink()) throw new Error("signed deployment journal pathname changed during reconciliation");
  };
  if (record.planDigest !== planDigest) throw new Error("signed deployment plan changed during reconciliation");
  const step = record.steps[index];
  if (step.state === "planned") return { state: "planned", step };
  const receipt = await provider.getTransactionReceipt(step.expectedHash);
  assertPinnedJournal();
  if (receipt) {
    if (!secondaryProvider) throw new Error("secondary independently configured RPC provider is required for mined deployment evidence");
    if (receipt.status !== 1 && receipt.status !== 1n) throw new Error(`deployment transaction reverted: ${step.expectedHash}`);
    await canonicalReceipt(provider, step, record.deployer, receipt, "primary");
    const secondaryReceipt = await secondaryProvider.getTransactionReceipt(step.expectedHash);
    assertPinnedJournal();
    if (!secondaryReceipt || (secondaryReceipt.status !== 1 && secondaryReceipt.status !== 1n)) throw new Error("secondary RPC does not corroborate mined deployment");
    await canonicalReceipt(secondaryProvider, step, record.deployer, secondaryReceipt, "secondary");
    if (
      secondaryReceipt.blockHash.toLowerCase() !== receipt.blockHash.toLowerCase() ||
      Number(secondaryReceipt.blockNumber) !== Number(receipt.blockNumber) ||
      (secondaryReceipt.contractAddress?.toLowerCase() ?? null) !== (receipt.contractAddress?.toLowerCase() ?? null)
    ) throw new Error("independent RPC providers disagree on deployment receipt");
    if (!Number.isSafeInteger(requiredConfirmations) || requiredConfirmations < 1) throw new Error("required deployment confirmations must be a positive integer");
    const [primaryHead, secondaryHead] = await Promise.all([provider.getBlockNumber(), secondaryProvider.getBlockNumber()]);
    assertPinnedJournal();
    const finalBlock = Number(receipt.blockNumber) + requiredConfirmations - 1;
    if (primaryHead < finalBlock || secondaryHead < finalBlock) throw new Error(`deployment lacks ${requiredConfirmations} independently corroborated confirmations`);
    const [finalPrimaryReceipt, finalSecondaryReceipt] = await Promise.all([
      provider.getTransactionReceipt(step.expectedHash), secondaryProvider.getTransactionReceipt(step.expectedHash),
    ]);
    assertPinnedJournal();
    if (!finalPrimaryReceipt || !finalSecondaryReceipt) throw new Error("deployment receipt disappeared at finality transition");
    if ((finalPrimaryReceipt.status !== 1 && finalPrimaryReceipt.status !== 1n) || (finalSecondaryReceipt.status !== 1 && finalSecondaryReceipt.status !== 1n)) {
      throw new Error("deployment receipt status changed before mined transition");
    }
    await canonicalReceipt(provider, step, record.deployer, finalPrimaryReceipt, "final primary", true);
    await canonicalReceipt(secondaryProvider, step, record.deployer, finalSecondaryReceipt, "final secondary", true);
    assertPinnedJournal();
    for (const candidate of [finalPrimaryReceipt, finalSecondaryReceipt]) {
      if (
        candidate.blockHash.toLowerCase() !== receipt.blockHash.toLowerCase() ||
        Number(candidate.blockNumber) !== Number(receipt.blockNumber) ||
        canonicalReceiptTransactionHash(candidate, "final deployment") !== step.expectedHash.toLowerCase() ||
        (step.kind === "direct-create" && candidate.contractAddress?.toLowerCase() !== step.address.toLowerCase()) ||
        (step.kind === "factory-call-create2" && candidate.contractAddress !== null)
      ) throw new Error("deployment evidence changed immediately before mined transition");
    }
    record = recordDeploymentMined(journalPath, planDigest, index, Number(finalPrimaryReceipt.blockNumber));
    return { state: "mined", step: record.steps[index], receipt: finalPrimaryReceipt };
  }
  const pending = await provider.getTransaction(step.expectedHash);
  assertPinnedJournal();
  if (pending) {
    if (pending.hash.toLowerCase() !== step.expectedHash.toLowerCase() || Number(pending.nonce) !== step.nonce || pending.from.toLowerCase() !== record.deployer.toLowerCase()) {
      throw new Error("pending transaction identity drift");
    }
    if (step.state === "signed") record = recordDeploymentBroadcast(journalPath, planDigest, index);
    return { state: "pending", step: record.steps[index] };
  }
  const latestNonce = await provider.getTransactionCount(record.deployer, "latest");
  const pendingNonce = await provider.getTransactionCount(record.deployer, "pending");
  assertPinnedJournal();
  if (latestNonce > step.nonce || pendingNonce > step.nonce) throw new Error(`nonce drift at ${step.nonce}; refusing replacement transaction`);
  if (latestNonce < record.startNonce || pendingNonce < record.startNonce) throw new Error("account nonce moved behind reserved deployment range");
  if (!allowBroadcast) return { state: "absent", step };
  assertPinnedJournal();
  const response = await provider.broadcastTransaction(step.rawTransaction);
  assertPinnedJournal();
  if (response.hash.toLowerCase() !== step.expectedHash.toLowerCase()) throw new Error("provider returned a different transaction hash");
  record = recordDeploymentBroadcast(journalPath, planDigest, index);
  return { state: "broadcast", step: record.steps[index], response };
}

export async function reconcileSignedDeployment(args) {
  return withDurableJournalLock(args.journalPath, () => reconcileLocked({ ...args, allowBroadcast: args.allowBroadcast ?? true }), args.lockHooks);
}

export function readSignedDeploymentJournal(path) {
  return readJournal(path);
}
