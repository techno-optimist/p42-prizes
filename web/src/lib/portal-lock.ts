import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { hostname, platform } from "node:os";
import path from "node:path";

const LOCK_SCHEMA = "p42-portal-state-lock-owner/v1";
const OWNER_MAX_BYTES = 2_048;

export interface PortalStateLockOwner {
  schemaVersion: typeof LOCK_SCHEMA;
  token: string;
  pid: number;
  hostname: string;
  processIdentity: string;
  processStartedAt: string;
  lockCreatedAt: string;
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function isoTimestamp(value: unknown): value is string {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function ownerBytes(owner: PortalStateLockOwner): string {
  return `${JSON.stringify(owner)}\n`;
}

function assertPrivateDirectory(directory: string): void {
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error("portal state lock path is not a private directory");
  }
  if ((stat.mode & 0o077) !== 0) throw new Error("portal state lock directory is not private");
}

export function readPortalStateLockOwner(lockPath: string): PortalStateLockOwner {
  assertPrivateDirectory(lockPath);
  const ownerPath = path.join(lockPath, "owner.json");
  const stat = lstatSync(ownerPath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0) {
    throw new Error("portal state lock owner file is unsafe");
  }
  if (stat.size < 2 || stat.size > OWNER_MAX_BYTES) throw new Error("portal state lock owner size is invalid");
  const raw = readFileSync(ownerPath, "utf8");
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("portal state lock owner JSON is invalid");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("portal state lock owner record is invalid");
  }
  const owner = value as Partial<PortalStateLockOwner>;
  const keys = Object.keys(owner).sort();
  const expectedKeys = [
    "hostname", "lockCreatedAt", "pid", "processIdentity", "processStartedAt", "schemaVersion", "token",
  ];
  if (JSON.stringify(keys) !== JSON.stringify(expectedKeys)
    || owner.schemaVersion !== LOCK_SCHEMA
    || !/^[a-f0-9]{64}$/.test(owner.token ?? "")
    || !Number.isSafeInteger(owner.pid) || Number(owner.pid) < 1
    || typeof owner.hostname !== "string" || owner.hostname.length < 1 || owner.hostname.length > 255
    || typeof owner.processIdentity !== "string"
    || owner.processIdentity.length < 1 || owner.processIdentity.length > 512
    || !isoTimestamp(owner.processStartedAt)
    || !isoTimestamp(owner.lockCreatedAt)) {
    throw new Error("portal state lock owner record is invalid");
  }
  const complete = owner as PortalStateLockOwner;
  if (raw !== ownerBytes(complete)) throw new Error("portal state lock owner encoding is non-canonical");
  return complete;
}

function writeOwner(lockPath: string, owner: PortalStateLockOwner): void {
  const ownerPath = path.join(lockPath, "owner.json");
  const fd = openSync(ownerPath, "wx", 0o600);
  try {
    writeFileSync(fd, ownerBytes(owner), "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  const directoryFd = openSync(lockPath, "r");
  try {
    fsyncSync(directoryFd);
  } finally {
    closeSync(directoryFd);
  }
}

export function processStartIdentity(pid: number): string | undefined {
  if (!Number.isSafeInteger(pid) || pid < 1) return undefined;
  if (platform() === "linux") {
    try {
      const bootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8").trim();
      const closeParen = stat.lastIndexOf(")");
      if (!/^[a-f0-9-]{36}$/.test(bootId) || closeParen < 2) return undefined;
      const fieldsAfterCommand = stat.slice(closeParen + 1).trim().split(/\s+/);
      const startTicks = fieldsAfterCommand[19];
      if (!/^\d+$/.test(startTicks ?? "")) return undefined;
      return `linux:${bootId}:${startTicks}`;
    } catch {
      return undefined;
    }
  }
  if (platform() === "darwin") {
    try {
      const started = execFileSync("/bin/ps", ["-o", "lstart=", "-p", String(pid)], {
        encoding: "utf8",
        env: { ...process.env, TZ: "UTC", LC_ALL: "C", LANG: "C" },
        stdio: ["ignore", "pipe", "ignore"],
      }).trim().replace(/\s+/g, " ");
      return started ? `darwin:${started}` : undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

type ProcessIdentityProbe = (pid: number) => string | undefined;
type ProcessLivenessProbe = (pid: number) => "alive" | "dead" | "denied";

function processLiveness(pid: number): "alive" | "dead" | "denied" {
  try {
    process.kill(pid, 0);
    return "alive";
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return "dead";
    if (code === "EPERM") return "denied";
    throw error;
  }
}

function ownerIsDeadOnThisHost(
  owner: PortalStateLockOwner,
  identityProbe: ProcessIdentityProbe,
  livenessProbe: ProcessLivenessProbe,
): boolean {
  if (owner.hostname !== hostname()) return false;
  const liveness = livenessProbe(owner.pid);
  if (liveness === "dead") return true;
  if (liveness === "denied") return false;
  const currentIdentity = identityProbe(owner.pid);
  return currentIdentity !== undefined && currentIdentity !== owner.processIdentity;
}

function sameOwner(left: PortalStateLockOwner, right: PortalStateLockOwner): boolean {
  return ownerBytes(left) === ownerBytes(right);
}

function reclaimDeadOwner(
  lockPath: string,
  observed: PortalStateLockOwner,
  identityProbe: ProcessIdentityProbe,
  livenessProbe: ProcessLivenessProbe,
): boolean {
  const reclaimPath = `${lockPath}.reclaim`;
  try {
    mkdirSync(reclaimPath, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw error;
  }
  try {
    let current: PortalStateLockOwner;
    try {
      current = readPortalStateLockOwner(lockPath);
    } catch (error) {
      // Another lock holder may have completed release or reclamation before
      // this contender acquired the reclaim mutex. Retry normal acquisition.
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    }
    if (!sameOwner(current, observed)
      || !ownerIsDeadOnThisHost(current, identityProbe, livenessProbe)) return false;
    const tombstone = `${lockPath}.dead.${current.token}`;
    renameSync(lockPath, tombstone);
    const moved = readPortalStateLockOwner(tombstone);
    if (!sameOwner(moved, current)) {
      if (!existsSync(lockPath)) renameSync(tombstone, lockPath);
      throw new Error("portal state lock changed during reclaim");
    }
    rmSync(tombstone, { recursive: true });
    return true;
  } finally {
    rmSync(reclaimPath, { recursive: true, force: true });
  }
}

export function acquirePortalStateLock(
  lockPath: string,
  options: {
    timeoutMs?: number;
    now?: () => number;
    processIdentityProbe?: ProcessIdentityProbe;
    processLivenessProbe?: ProcessLivenessProbe;
  } = {},
): PortalStateLockOwner {
  const timeoutMs = options.timeoutMs ?? 5_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0) throw new Error("portal state lock timeout is invalid");
  const now = options.now ?? Date.now;
  const identityProbe = options.processIdentityProbe ?? processStartIdentity;
  const livenessProbe = options.processLivenessProbe ?? processLiveness;
  const ownProcessIdentity = identityProbe(process.pid);
  if (ownProcessIdentity === undefined) {
    throw new Error("portal state lock cannot establish this process start identity");
  }
  const startedAt = Date.now();
  let incompleteOwnerError: Error | undefined;
  for (;;) {
    if (existsSync(`${lockPath}.reclaim`)) {
      if (Date.now() - startedAt >= timeoutMs) throw new Error("timed out acquiring portal state lock");
      sleepSync(25);
      continue;
    }
    const owner: PortalStateLockOwner = {
      schemaVersion: LOCK_SCHEMA,
      token: randomBytes(32).toString("hex"),
      pid: process.pid,
      hostname: hostname(),
      processIdentity: ownProcessIdentity,
      processStartedAt: new Date(Date.now() - Math.floor(process.uptime() * 1_000)).toISOString(),
      lockCreatedAt: new Date(now()).toISOString(),
    };
    const candidatePath = `${lockPath}.candidate.${owner.pid}.${owner.token}`;
    try {
      mkdirSync(candidatePath, { mode: 0o700 });
      writeOwner(candidatePath, owner);
      renameSync(candidatePath, lockPath);
      return owner;
    } catch (error) {
      rmSync(candidatePath, { recursive: true, force: true });
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "EEXIST" && code !== "ENOTEMPTY") throw error;
      let observed: PortalStateLockOwner;
      try {
        observed = readPortalStateLockOwner(lockPath);
      } catch (readError) {
        if ((readError as NodeJS.ErrnoException).code === "ENOENT") continue;
        incompleteOwnerError = readError as Error;
        if (Date.now() - startedAt >= timeoutMs) {
          throw new Error(`portal state lock is incomplete; refusing reclaim: ${incompleteOwnerError.message}`);
        }
        sleepSync(25);
        continue;
      }
      incompleteOwnerError = undefined;
      if (ownerIsDeadOnThisHost(observed, identityProbe, livenessProbe)
        && reclaimDeadOwner(lockPath, observed, identityProbe, livenessProbe)) continue;
      if (Date.now() - startedAt >= timeoutMs) throw new Error("timed out acquiring portal state lock");
      sleepSync(25);
    }
  }
}

export function releasePortalStateLock(lockPath: string, owner: PortalStateLockOwner): void {
  const current = readPortalStateLockOwner(lockPath);
  if (!sameOwner(current, owner)) throw new Error("portal state lock release token mismatch");
  const tombstone = `${lockPath}.release.${owner.token}`;
  renameSync(lockPath, tombstone);
  const moved = readPortalStateLockOwner(tombstone);
  if (!sameOwner(moved, owner)) {
    if (!existsSync(lockPath)) renameSync(tombstone, lockPath);
    throw new Error("portal state lock changed during release");
  }
  rmSync(tombstone, { recursive: true });
}

export function withPortalStateFileLock<T>(
  lockPath: string,
  operation: () => T,
  options: {
    timeoutMs?: number;
    now?: () => number;
    processIdentityProbe?: ProcessIdentityProbe;
    processLivenessProbe?: ProcessLivenessProbe;
  } = {},
): T {
  const owner = acquirePortalStateLock(lockPath, options);
  try {
    return operation();
  } finally {
    releasePortalStateLock(lockPath, owner);
  }
}
