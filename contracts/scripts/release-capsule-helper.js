import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { link, lstat, mkdir, mkdtemp, open, readFile, readdir, rm, symlink, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { readStrictJsonFile, readStrictJsonFileSync } from "../../agent/strict-json.mjs";

export const RELEASE_CAPSULE_SCHEMA = "p42-prizes/release-capsule/v2";
export const PRODUCTION_CONTRACTS = Object.freeze([
  "P42MultisigTimelock",
  "P42ChallengeManagerFactory",
  "P42SubmissionManagerFactory",
  "P42RolloverVault",
  "P42SP1VerifierGateway",
  "P42ResolverQuorum",
  "P42BountyPool",
  "P42PayoutLedger",
  "P42SubmissionManager",
  "P42ChallengeManager",
  "P42ProblemRegistry",
]);
const EXTERNAL_DEPENDENCIES_PATH = fileURLToPath(new URL("../../protocol/external-dependencies-v1.json", import.meta.url));
const externalDependencyPolicy = readStrictJsonFileSync(EXTERNAL_DEPENDENCIES_PATH, { maxBytes: 64 * 1024, maxDepth: 16 });
export const PRODUCTION_EXTERNAL_DEPENDENCIES = Object.freeze(structuredClone(externalDependencyPolicy.dependencies));

const HEX_RE = /^0x(?:[0-9a-f]{2})*$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const ARTIFACT_KEYS = ["_format", "contractName", "sourceName", "abi", "bytecode", "deployedBytecode", "linkReferences", "deployedLinkReferences", "immutableReferences", "inputSourceName", "buildInfoId"];
const CONTRACT_KEYS = ["name", "sourceName", "buildInfoId", "artifactDigest", "abi", "creationCode", "runtimeTemplate", "immutableReferences", "immutableBindings", "linkReferences", "deployedLinkReferences"];
const BUILD_INFO_KEYS = ["id", "inputDigest", "outputDigest", "compiler", "settings", "input", "output"];
const BINDING_KEYS = ["astId", "name", "type", "ranges"];
const RANGE_KEYS = ["start", "length"];
const STRICT_JSON = Object.freeze({ maxBytes: 8 * 1024 * 1024, maxDepth: 256, trailingNewline: "allow" });

const IMMUTABLE_SEMANTICS = Object.freeze({
  P42MultisigTimelock: Object.freeze(["delay", "overrideDelay", "operationGracePeriod"]),
  P42ChallengeManagerFactory: Object.freeze([]),
  P42SubmissionManagerFactory: Object.freeze([]),
  P42RolloverVault: Object.freeze([]),
  P42SP1VerifierGateway: Object.freeze([]),
  P42ResolverQuorum: Object.freeze(["owner", "expectedTreasury", "expectedDecisionBondWei", "managerFactory", "objectiveVerifier", "objectiveVerifierCodehash"]),
  P42BountyPool: Object.freeze(["owner", "fundingCap"]),
  P42PayoutLedger: Object.freeze(["owner", "pool", "treasury", "feeBps", "earliestCloseTimestamp", "closeByTimestamp"]),
  P42SubmissionManager: Object.freeze(["owner", "treasury", "fundingAuthorizer", "boardSetDigest", "releaseBindingDigest", "productionLaunchAuthority", "independentSecurityAuthority", "governanceAuthority", "pool", "ledger", "alphaBps", "minPostingBondWei", "challengeWindowSeconds", "deployedAt", "armNotBefore", "onchainDa", "maxSolutionBytes", "seedScoreAtoms", "minImprovementAtoms"]),
  P42ChallengeManager: Object.freeze(["owner", "resolver", "treasury", "submissionManager", "challengeWindowSeconds", "betaBps", "rerunCostMultiplierBps", "minCounterBondWei", "rerunCostWei", "resolverDecisionBondWei", "resolverFraudWindowSeconds"]),
  P42ProblemRegistry: Object.freeze(["owner"]),
});

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

export function sha256(value) {
  const bytes = Buffer.isBuffer(value) || value instanceof Uint8Array ? value : Buffer.from(String(value));
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function canonicalDigest(value) {
  return sha256(canonical(value));
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const missing = keys.filter((key) => !Object.hasOwn(value, key));
  const extra = Object.keys(value).filter((key) => !keys.includes(key));
  if (missing.length || extra.length) throw new Error(`${label} keys mismatch (missing: ${missing.join(",") || "none"}; extra: ${extra.join(",") || "none"})`);
}

function strictRead(path) {
  return readStrictJsonFile(path, STRICT_JSON);
}

export function readReleaseBuildJson(path) {
  return strictRead(path);
}

function assertHex(value, label) {
  if (typeof value !== "string" || !HEX_RE.test(value)) throw new Error(`${label} must be lowercase even-length hex`);
}

function walk(node, visit) {
  if (!node || typeof node !== "object") return;
  visit(node);
  for (const value of Object.values(node)) Array.isArray(value) ? value.forEach((item) => walk(item, visit)) : walk(value, visit);
}

function immutableDeclarations(ast, contractName) {
  let contract;
  walk(ast, (node) => {
    if (node.nodeType === "ContractDefinition" && node.name === contractName) contract = node;
  });
  if (!contract) throw new Error(`AST contract ${contractName} not found`);
  const declarations = new Map();
  walk(contract, (node) => {
    if (node.nodeType === "VariableDeclaration" && node.stateVariable === true && node.mutability === "immutable") {
      declarations.set(String(node.id), { astId: String(node.id), name: node.name, type: node.typeDescriptions?.typeString ?? "" });
    }
  });
  return declarations;
}

function sourceAst(buildOutput, artifact) {
  const source = buildOutput.output?.sources?.[artifact.inputSourceName];
  if (!source?.ast) throw new Error(`${artifact.contractName} build output has no source AST`);
  return source.ast;
}

function outputContract(buildOutput, artifact) {
  const contract = buildOutput.output?.contracts?.[artifact.inputSourceName]?.[artifact.contractName];
  if (!contract) throw new Error(`${artifact.contractName} is absent from its build output`);
  return contract;
}

function immutableBindings(artifact, buildOutput) {
  const declarations = immutableDeclarations(sourceAst(buildOutput, artifact), artifact.contractName);
  const bindings = Object.entries(artifact.immutableReferences).map(([astId, ranges]) => {
    const declaration = declarations.get(astId);
    if (!declaration) throw new Error(`${artifact.contractName} immutable reference has unknown AST id ${astId}`);
    return { ...declaration, ranges: ranges.map(({ start, length }) => ({ start, length })) };
  });
  for (const astId of declarations.keys()) {
    if (!Object.hasOwn(artifact.immutableReferences, astId)) throw new Error(`${artifact.contractName} immutable AST id ${astId} has no bytecode reference`);
  }
  const actual = [...declarations.values()].map(({ name }) => name).sort();
  const expected = [...IMMUTABLE_SEMANTICS[artifact.contractName]].sort();
  if (canonical(actual) !== canonical(expected)) throw new Error(`${artifact.contractName} immutable semantic set differs from the explicit release policy`);
  return bindings.sort((a, b) => Number(a.astId) - Number(b.astId));
}

function artifactView(artifact) {
  return {
    _format: artifact._format,
    contractName: artifact.contractName,
    sourceName: artifact.sourceName,
    abi: artifact.abi,
    bytecode: artifact.bytecode,
    deployedBytecode: artifact.deployedBytecode,
    linkReferences: artifact.linkReferences,
    deployedLinkReferences: artifact.deployedLinkReferences,
    immutableReferences: artifact.immutableReferences,
    inputSourceName: artifact.inputSourceName,
    buildInfoId: artifact.buildInfoId,
  };
}

export function validateContractArtifact(artifact, buildInput, buildOutput, { expectedName } = {}) {
  if (!artifact || artifact.contractName !== (expectedName ?? artifact.contractName)) throw new Error("artifact contract name mismatch");
  exactKeys(artifact, ARTIFACT_KEYS, `${artifact?.contractName ?? "contract"} artifact`);
  if (buildInput.id !== artifact.buildInfoId || buildOutput.id !== artifact.buildInfoId) throw new Error(`${artifact.contractName} wrong build-info identity`);
  if (buildInput.solcVersion !== "0.8.24" || buildInput.solcLongVersion !== "0.8.24+commit.e11b9ed9") throw new Error(`${artifact.contractName} compiler drift`);
  const settings = buildInput.input?.settings;
  if (settings?.optimizer?.enabled !== true || settings.optimizer.runs !== 200 || settings.evmVersion !== "shanghai") throw new Error(`${artifact.contractName} compiler settings drift`);
  if (Object.keys(artifact.linkReferences).length || Object.keys(artifact.deployedLinkReferences).length) throw new Error(`${artifact.contractName} contains forbidden link references`);
  assertHex(artifact.bytecode, `${artifact.contractName} creation bytecode`);
  assertHex(artifact.deployedBytecode, `${artifact.contractName} runtime bytecode`);
  const compiled = outputContract(buildOutput, artifact);
  if (canonical(compiled.abi) !== canonical(artifact.abi) || `0x${compiled.evm.bytecode.object}` !== artifact.bytecode || `0x${compiled.evm.deployedBytecode.object}` !== artifact.deployedBytecode) throw new Error(`${artifact.contractName} artifact differs from build output`);
  if (canonical(compiled.evm.bytecode.linkReferences) !== canonical(artifact.linkReferences) || canonical(compiled.evm.deployedBytecode.linkReferences) !== canonical(artifact.deployedLinkReferences) || canonical(compiled.evm.deployedBytecode.immutableReferences) !== canonical(artifact.immutableReferences)) throw new Error(`${artifact.contractName} reference metadata differs from build output`);
  return immutableBindings(artifact, buildOutput);
}

export async function createReleaseCapsule({ contractsRoot = process.cwd(), gitCommit } = {}) {
  if (!/^[0-9a-f]{40}$/.test(gitCommit ?? "")) throw new Error("release capsule requires a full lowercase git commit");
  const entries = [];
  const buildInfos = new Map();
  for (const name of PRODUCTION_CONTRACTS) {
    const artifactPath = join(contractsRoot, "artifacts", "src", `${name}.sol`, `${name}.json`);
    const artifact = await readReleaseBuildJson(artifactPath);
    const inputPath = join(contractsRoot, "artifacts", "build-info", `${artifact.buildInfoId}.json`);
    const outputPath = join(contractsRoot, "artifacts", "build-info", `${artifact.buildInfoId}.output.json`);
    const [buildInput, buildOutput] = await Promise.all([readReleaseBuildJson(inputPath), readReleaseBuildJson(outputPath)]);
    const immutables = validateContractArtifact(artifact, buildInput, buildOutput, { expectedName: name });
    entries.push({
      name, sourceName: artifact.sourceName, buildInfoId: artifact.buildInfoId,
      artifactDigest: canonicalDigest(artifact), abi: artifact.abi, creationCode: artifact.bytecode,
      runtimeTemplate: artifact.deployedBytecode, immutableReferences: artifact.immutableReferences,
      immutableBindings: immutables, linkReferences: artifact.linkReferences, deployedLinkReferences: artifact.deployedLinkReferences,
    });
    const prior = buildInfos.get(artifact.buildInfoId);
    const record = { id: artifact.buildInfoId, inputDigest: canonicalDigest(buildInput), outputDigest: canonicalDigest(buildOutput), compiler: { version: buildInput.solcVersion, longVersion: buildInput.solcLongVersion }, settings: buildInput.input.settings, input: buildInput, output: buildOutput };
    if (prior && (prior.inputDigest !== record.inputDigest || prior.outputDigest !== record.outputDigest)) throw new Error(`conflicting build-info ${artifact.buildInfoId}`);
    buildInfos.set(artifact.buildInfoId, record);
  }
  const body = {
    schema: RELEASE_CAPSULE_SCHEMA,
    gitCommit,
    contracts: entries,
    externalDependencies: structuredClone(PRODUCTION_EXTERNAL_DEPENDENCIES),
    buildInfos: [...buildInfos.values()].sort((a, b) => a.id.localeCompare(b.id)),
  };
  return { ...body, capsuleDigest: canonicalDigest(body) };
}

function validateRanges(contract) {
  const byteLength = (contract.runtimeTemplate.length - 2) / 2;
  const occupied = [];
  const ids = new Set();
  for (const binding of contract.immutableBindings) {
    exactKeys(binding, BINDING_KEYS, `${contract.name} immutable binding`);
    if (ids.has(binding.astId)) throw new Error(`${contract.name} duplicate immutable AST id ${binding.astId}`);
    ids.add(binding.astId);
    if (!Object.hasOwn(contract.immutableReferences, binding.astId)) throw new Error(`${contract.name} immutable binding has unknown AST id ${binding.astId}`);
    if (canonical(binding.ranges) !== canonical(contract.immutableReferences[binding.astId])) throw new Error(`${contract.name} immutable ranges differ for AST id ${binding.astId}`);
    for (const range of binding.ranges) {
      exactKeys(range, RANGE_KEYS, `${contract.name} immutable range`);
      if (!Number.isSafeInteger(range.start) || !Number.isSafeInteger(range.length) || range.start < 0 || range.length < 1 || range.start + range.length > byteLength) throw new Error(`${contract.name} immutable range out of bounds`);
      for (const previous of occupied) if (range.start < previous.end && previous.start < range.start + range.length) throw new Error(`${contract.name} immutable ranges overlap`);
      occupied.push({ start: range.start, end: range.start + range.length });
    }
  }
  if (Object.keys(contract.immutableReferences).some((id) => !ids.has(id))) throw new Error(`${contract.name} immutable references contain unknown IDs`);
  return occupied;
}

export function validateReleaseCapsule(capsule) {
  exactKeys(capsule, ["schema", "gitCommit", "contracts", "externalDependencies", "buildInfos", "capsuleDigest"], "release capsule");
  if (capsule.schema !== RELEASE_CAPSULE_SCHEMA || !/^[0-9a-f]{40}$/.test(capsule.gitCommit) || !DIGEST_RE.test(capsule.capsuleDigest)) throw new Error("invalid release capsule identity");
  if (capsule.contracts.map(({ name }) => name).join("\0") !== PRODUCTION_CONTRACTS.join("\0")) throw new Error("release capsule must contain exactly the eleven production artifacts in canonical order");
  if (canonical(capsule.externalDependencies) !== canonical(PRODUCTION_EXTERNAL_DEPENDENCIES)) throw new Error("release capsule external dependency policy mismatch");
  const infos = new Map(capsule.buildInfos.map((info) => [info.id, info]));
  if (infos.size !== capsule.buildInfos.length) throw new Error("duplicate build-info identity");
  for (const info of capsule.buildInfos) {
    exactKeys(info, BUILD_INFO_KEYS, "release capsule build-info");
    exactKeys(info.compiler, ["version", "longVersion"], `${info.id} compiler`);
    if (canonicalDigest(info.input) !== info.inputDigest) throw new Error(`${info.id} build-info input digest mismatch`);
    if (canonicalDigest(info.output) !== info.outputDigest) throw new Error(`${info.id} build-info output digest mismatch`);
    if (info.input.id !== info.id || info.output.id !== info.id || canonical(info.input.input.settings) !== canonical(info.settings) || info.input.solcVersion !== info.compiler.version || info.input.solcLongVersion !== info.compiler.longVersion) throw new Error(`${info.id} compiler/build-info binding mismatch`);
  }
  for (const contract of capsule.contracts) {
    exactKeys(contract, CONTRACT_KEYS, "release capsule contract");
    assertHex(contract.creationCode, `${contract.name} creation code`); assertHex(contract.runtimeTemplate, `${contract.name} runtime template`);
    if (Object.keys(contract.linkReferences).length || Object.keys(contract.deployedLinkReferences).length) throw new Error(`${contract.name} contains forbidden link references`);
    validateRanges(contract);
    const info = infos.get(contract.buildInfoId);
    if (!info) throw new Error(`${contract.name} references unknown build-info`);
    const artifact = artifactView({ _format: "hh3-artifact-1", contractName: contract.name, sourceName: contract.sourceName, abi: contract.abi, bytecode: contract.creationCode, deployedBytecode: contract.runtimeTemplate, linkReferences: contract.linkReferences, deployedLinkReferences: contract.deployedLinkReferences, immutableReferences: contract.immutableReferences, inputSourceName: `project/${contract.sourceName}`, buildInfoId: contract.buildInfoId });
    if (canonicalDigest(artifact) !== contract.artifactDigest) throw new Error(`${contract.name} artifact digest mismatch`);
    validateContractArtifact(artifact, info.input, info.output, { expectedName: contract.name });
  }
  const { capsuleDigest, ...body } = capsule;
  if (canonicalDigest(body) !== capsuleDigest) throw new Error("release capsule digest mismatch");
  return capsule;
}

function encodedWord(value, type, length) {
  let integer;
  if (typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value)) integer = BigInt(value);
  else if (typeof value === "boolean") integer = value ? 1n : 0n;
  else integer = BigInt(value);
  const bits = BigInt(length * 8);
  const signed = type.startsWith("int") && !type.startsWith("interface") && !type.startsWith("contract");
  const limit = 1n << bits;
  if (signed && integer < 0) integer = limit + integer;
  if (integer < 0 || integer >= limit) throw new Error(`immutable value ${value} does not fit ${length} bytes`);
  return integer.toString(16).padStart(length * 2, "0");
}

export function reconstructExpectedRuntime(contract, values) {
  assertHex(contract.runtimeTemplate, `${contract.name} runtime template`);
  validateRanges(contract);
  const allowed = new Set(contract.immutableBindings.flatMap((binding) => [binding.name, binding.astId]));
  for (const key of Object.keys(values)) if (!allowed.has(key)) throw new Error(`${contract.name} unknown immutable value ${key}`);
  const bytes = contract.runtimeTemplate.slice(2).split("");
  for (const binding of contract.immutableBindings) {
    const hasName = Object.hasOwn(values, binding.name), hasId = Object.hasOwn(values, binding.astId);
    if (hasName === hasId && (hasName || !hasName)) {
      if (!hasName) throw new Error(`${contract.name} missing immutable value ${binding.name}`);
      throw new Error(`${contract.name} immutable ${binding.name} supplied twice`);
    }
    const value = values[hasName ? binding.name : binding.astId];
    for (const range of binding.ranges) bytes.splice(range.start * 2, range.length * 2, ...encodedWord(value, binding.type, range.length));
  }
  return `0x${bytes.join("")}`;
}

export function assertRuntimeMatches(contract, actualRuntime, values) {
  assertHex(actualRuntime, `${contract.name} actual runtime`);
  const expected = reconstructExpectedRuntime(contract, values);
  if (actualRuntime !== expected) throw new Error(`${contract.name} deployed runtime mismatch`);
  return true;
}

export function immutableValuesFromConstructor(contract, constructorArgs, { blockTimestamp } = {}) {
  const constructor = contract.abi.find((entry) => entry.type === "constructor") ?? { inputs: [] };
  if (!Array.isArray(constructorArgs) || constructorArgs.length !== constructor.inputs.length) throw new Error(`${contract.name} constructor argument count mismatch`);
  const values = {};
  const names = new Set(contract.immutableBindings.map(({ name }) => name));
  constructor.inputs.forEach((input, index) => {
    const candidate = input.name.replace(/_$/, "");
    if (names.has(candidate)) values[candidate] = constructorArgs[index];
  });
  if (contract.name === "P42MultisigTimelock") {
    const delayIndex = constructor.inputs.findIndex(({ name }) => name === "delaySeconds_");
    const delay = BigInt(constructorArgs[delayIndex]);
    values.delay = delay;
    values.overrideDelay = delay * 2n;
    values.operationGracePeriod = 7n * 24n * 60n * 60n;
  }
  if (contract.name === "P42SubmissionManager") {
    if (!Number.isSafeInteger(blockTimestamp) || blockTimestamp < 0) throw new Error("P42SubmissionManager requires the deployment block timestamp");
    const deployment = constructorArgs[0];
    const funding = constructorArgs[1];
    const field = (value, index, name) => Array.isArray(value) ? value[index] : value?.[name];
    for (const [index, name] of [
      "pool", "ledger", "owner", "treasury", "alphaBps", "minPostingBondWei",
      "challengeWindowSeconds", "onchainDa", "maxSolutionBytes", "seedScoreAtoms", "minImprovementAtoms",
    ].entries()) values[name] = field(deployment, index, name);
    for (const [index, name] of [
      "boardSetDigest", "releaseBindingDigest", "productionLaunchAuthority",
      "independentSecurityAuthority", "governanceAuthority",
    ].entries()) values[name] = field(funding, index, name);
    values.deployedAt = blockTimestamp;
    values.armNotBefore = BigInt(blockTimestamp) + BigInt(values.challengeWindowSeconds);
    values.fundingAuthorizer = values.treasury;
  }
  return values;
}

function checkoutState(repoRoot, run) {
  const commit = run("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).trim();
  const status = run("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: repoRoot, encoding: "utf8" });
  return { commit, status };
}

export async function attestReleaseCapsuleAgainstCheckout(capsule, {
  repoRoot,
  expectedGitCommit,
  run = execFileSync,
  rebuild = createReleaseCapsule,
} = {}) {
  validateReleaseCapsule(capsule);
  const root = resolve(repoRoot ?? "");
  if (!repoRoot || !/^[0-9a-f]{40}$/.test(expectedGitCommit ?? "")) throw new Error("checkout attestation requires a trusted root and exact expected git commit");
  if (capsule.gitCommit !== expectedGitCommit) throw new Error("capsule git commit differs from trusted expected commit");
  const before = checkoutState(root, run);
  if (before.commit !== expectedGitCommit) throw new Error("checkout HEAD differs from trusted expected commit");
  if (before.status !== "") throw new Error("checkout must be clean before release compilation");
  const hardhat = join(root, "contracts", "node_modules", ".bin", "hardhat");
  run(hardhat, ["compile", "--force"], { cwd: join(root, "contracts"), encoding: "utf8", stdio: "pipe" });
  const after = checkoutState(root, run);
  if (after.commit !== expectedGitCommit || after.status !== "") throw new Error("checkout changed during release compilation");
  const rebuilt = await rebuild({ contractsRoot: join(root, "contracts"), gitCommit: expectedGitCommit });
  validateReleaseCapsule(rebuilt);
  if (rebuilt.capsuleDigest !== capsule.capsuleDigest || canonical(rebuilt) !== canonical(capsule)) throw new Error("capsule provenance does not match forced source rebuild");
  return { capsuleDigest: capsule.capsuleDigest, gitCommit: expectedGitCommit, compiler: "hardhat:local-pinned-force" };
}

async function mountLocalNodeModules(source, target) {
  await mkdir(target, { mode: 0o700 });
  for (const entry of await readdir(source)) {
    await symlink(join(source, entry), join(target, entry));
  }
}

export async function attestReleaseCapsuleAtCommit(capsule, {
  repoRoot,
  toolchainRoot = repoRoot,
  expectedGitCommit,
  run = execFileSync,
  attest = attestReleaseCapsuleAgainstCheckout,
  createTemporaryDirectory = mkdtemp,
  remove = rm,
  installLocalDependencies = mountLocalNodeModules,
} = {}) {
  validateReleaseCapsule(capsule);
  const root = resolve(repoRoot ?? "");
  if (!repoRoot || !/^[0-9a-f]{40}$/.test(expectedGitCommit ?? "")) throw new Error("detached checkout attestation requires a trusted root and exact expected git commit");
  if (capsule.gitCommit !== expectedGitCommit) throw new Error("capsule git commit differs from detached checkout commit");
  const resolvedCommit = run("git", ["rev-parse", "--verify", `${expectedGitCommit}^{commit}`], { cwd: root, encoding: "utf8" }).trim();
  if (resolvedCommit !== expectedGitCommit) throw new Error("detached checkout commit did not resolve exactly");

  const tools = resolve(toolchainRoot ?? "");
  const dependencyRoot = join(tools, "contracts", "node_modules");
  const dependencyMetadata = await lstat(dependencyRoot);
  if (!dependencyMetadata.isDirectory() || dependencyMetadata.isSymbolicLink()) throw new Error("release rebuild requires a local regular node_modules directory");
  const expectedLock = run("git", ["show", `${expectedGitCommit}:contracts/package-lock.json`], { cwd: root, encoding: null });
  const installedLock = await readFile(join(tools, "contracts", "package-lock.json"));
  if (!Buffer.from(expectedLock).equals(installedLock)) throw new Error("local release toolchain lock differs from the deployment commit");

  const temporaryRoot = await createTemporaryDirectory(join(tmpdir(), "p42-release-rebuild-"));
  const checkout = join(temporaryRoot, "checkout");
  let worktreeAdded = false;
  try {
    run("git", ["worktree", "add", "--detach", checkout, expectedGitCommit], { cwd: root, encoding: "utf8", stdio: "pipe" });
    worktreeAdded = true;
    await installLocalDependencies(dependencyRoot, join(checkout, "contracts", "node_modules"));
    return await attest(capsule, { repoRoot: checkout, expectedGitCommit, run });
  } finally {
    let removalError;
    if (worktreeAdded) {
      try {
        run("git", ["worktree", "remove", "--force", checkout], { cwd: root, encoding: "utf8", stdio: "pipe" });
      } catch (error) {
        removalError = error;
      }
    }
    await remove(temporaryRoot, { recursive: true, force: true });
    if (removalError) throw new Error("detached release checkout could not be removed safely", { cause: removalError });
  }
}

async function readExactDescriptor(handle, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const { bytesRead } = await handle.read(bytes, offset, size - offset, offset);
    if (bytesRead === 0) throw new Error("published capsule target was truncated during descriptor read");
    offset += bytesRead;
  }
  return bytes;
}

// Publication proves the named file at return time. A same-UID process can
// mutate it afterward; every consumer must recheck the content digest on read.
export async function publishReleaseCapsule(capsule, directory, {
  trustedRoot,
  storage = { open, link, lstat, unlink },
  beforeDirectoryFsync,
} = {}) {
  validateReleaseCapsule(capsule);
  const root = resolve(trustedRoot ?? "");
  const publicationDirectory = resolve(directory);
  const rel = relative(root, publicationDirectory);
  if (!trustedRoot || (rel && (rel === ".." || rel.startsWith(`..${sep}`)))) throw new Error("publication directory must be within an explicit trusted root");
  const held = [];
  for (const path of [root, ...(rel ? rel.split(sep).map((_, index, parts) => join(root, ...parts.slice(0, index + 1))) : [])]) {
    const handle = await storage.open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const metadata = await handle.stat();
    if (!metadata.isDirectory() || (typeof process.getuid === "function" && metadata.uid !== process.getuid()) || (metadata.mode & 0o022) !== 0) throw new Error("publication trusted parent is unsafe");
    held.push({ path, handle, metadata });
  }
  const parent = held.at(-1);
  const hex = capsule.capsuleDigest.slice("sha256:".length);
  const target = join(publicationDirectory, `${hex}.json`);
  const descriptorTarget = target;
  const bytes = Buffer.from(`${canonical(capsule)}\n`);
  const temporaryName = `.${basename(target)}.${process.pid}.${Date.now()}.tmp`;
  const descriptorTemporary = join(publicationDirectory, temporaryName);
  const assertParentsHeld = async () => {
    for (const entry of held) {
      const currentMetadata = await storage.lstat(entry.path);
      if (!currentMetadata.isDirectory() || currentMetadata.dev !== entry.metadata.dev || currentMetadata.ino !== entry.metadata.ino) throw new Error("publication trusted parent was replaced");
    }
  };
  let handle;
  let targetHandle;
  try {
    handle = await storage.open(descriptorTemporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o444);
    await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = undefined;
    await assertParentsHeld();
    try { await storage.link(descriptorTemporary, descriptorTarget); } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    await storage.unlink(descriptorTemporary);
    const before = await storage.lstat(descriptorTarget);
    targetHandle = await storage.open(descriptorTarget, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = await targetHandle.stat();
    if (!before.isFile() || !opened.isFile() || before.dev !== opened.dev || before.ino !== opened.ino || opened.nlink !== 1 || opened.size !== bytes.length || (opened.mode & 0o777) !== 0o444 || (typeof process.getuid === "function" && opened.uid !== process.getuid())) throw new Error("published capsule target metadata is unsafe");
    const stored = await readExactDescriptor(targetHandle, opened.size);
    const after = await storage.lstat(descriptorTarget);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size || after.nlink !== opened.nlink || (after.mode & 0o777) !== (opened.mode & 0o777)) throw new Error("published capsule target changed during validation");
    if (!stored.equals(bytes)) throw new Error("content-addressed capsule path contains different bytes");
    await assertParentsHeld();
    if (beforeDirectoryFsync) await beforeDirectoryFsync({ target, directory: publicationDirectory });
    await parent.handle.sync();
    const heldFinal = await targetHandle.stat();
    const finalPath = await storage.lstat(descriptorTarget);
    if (!heldFinal.isFile() || heldFinal.dev !== opened.dev || heldFinal.ino !== opened.ino || heldFinal.size !== bytes.length || heldFinal.nlink !== 1 || (heldFinal.mode & 0o777) !== 0o444) throw new Error("published capsule held descriptor changed before durable return");
    if (!finalPath.isFile() || finalPath.dev !== heldFinal.dev || finalPath.ino !== heldFinal.ino || finalPath.size !== heldFinal.size || finalPath.nlink !== heldFinal.nlink || (finalPath.mode & 0o777) !== (heldFinal.mode & 0o777)) throw new Error("published capsule target changed before durable return");
    const finalStored = await readExactDescriptor(targetHandle, heldFinal.size);
    if (!finalStored.equals(bytes)) throw new Error("published capsule descriptor bytes changed before durable return");
  } finally {
    if (handle) await handle.close();
    if (targetHandle) await targetHandle.close();
    try { await storage.unlink(descriptorTemporary); } catch {}
    for (const entry of held.reverse()) await entry.handle.close();
  }
  return { digest: capsule.capsuleDigest, uri: `sha256://${hex}`, path: target };
}
