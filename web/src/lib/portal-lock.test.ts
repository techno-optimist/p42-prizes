import { spawn, type ChildProcess } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { hostname, tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  acquirePortalStateLock,
  processStartIdentity,
  readPortalStateLockOwner,
  releasePortalStateLock,
} from "@/lib/portal-lock";

const moduleUrl = pathToFileURL(path.resolve("src/lib/portal-lock.ts")).href;
let root: string;
let lockPath: string;

function waitForExit(child: ChildProcess): Promise<{ code: number | null; stderr: string }> {
  let stderr = "";
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk) => { stderr += chunk; });
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve({ code, stderr }));
  });
}

async function waitForFile(filePath: string, timeoutMs = 3_000): Promise<void> {
  const started = Date.now();
  while (!existsSync(filePath)) {
    if (Date.now() - started > timeoutMs) throw new Error(`timed out waiting for ${filePath}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function nodeChild(source: string, ...args: string[]): ChildProcess {
  return spawn(
    process.execPath,
    ["--no-warnings", "--experimental-strip-types", "--input-type=module", "-e", source, moduleUrl, ...args],
    { stdio: ["ignore", "ignore", "pipe"] },
  );
}

function writeOwner(owner: Record<string, unknown>): void {
  mkdirSync(lockPath, { mode: 0o700 });
  chmodSync(lockPath, 0o700);
  const ownerPath = path.join(lockPath, "owner.json");
  writeFileSync(ownerPath, `${JSON.stringify(owner)}\n`, { encoding: "utf8", mode: 0o600 });
  chmodSync(ownerPath, 0o600);
}

describe("portal state lock ownership", () => {
  beforeEach(() => {
    root = mkdtempSync(path.join(tmpdir(), "p42-portal-lock-"));
    lockPath = path.join(root, "state.json.lock");
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("never evicts an arbitrarily old live owner", () => {
    const owner = acquirePortalStateLock(lockPath, { now: () => 0 });
    expect(() => acquirePortalStateLock(lockPath, { timeoutMs: 50 }))
      .toThrow("timed out acquiring portal state lock");
    expect(readPortalStateLockOwner(lockPath).token).toBe(owner.token);
    releasePortalStateLock(lockPath, owner);
  });

  it("reclaims a complete same-host lock only after its process exits", async () => {
    const child = nodeChild(`
      const { acquirePortalStateLock } = await import(process.argv[1]);
      acquirePortalStateLock(process.argv[2]);
    `, lockPath);
    const result = await waitForExit(child);
    expect(result).toEqual({ code: 0, stderr: "" });
    const deadOwner = readPortalStateLockOwner(lockPath);
    expect(deadOwner.pid).not.toBe(process.pid);

    const replacement = acquirePortalStateLock(lockPath, { timeoutMs: 1_000 });
    expect(replacement.token).not.toBe(deadOwner.token);
    releasePortalStateLock(lockPath, replacement);
  });

  it("fails closed for malformed and foreign-host owner records", () => {
    writeOwner({ pid: 999_999, createdAt: "2000-01-01T00:00:00.000Z" });
    expect(() => acquirePortalStateLock(lockPath, { timeoutMs: 20 }))
      .toThrow("portal state lock is incomplete; refusing reclaim");
    rmSync(lockPath, { recursive: true });

    writeOwner({
      schemaVersion: "p42-portal-state-lock-owner/v1",
      token: "a".repeat(64),
      pid: process.pid,
      hostname: `${hostname()}-foreign`,
      processIdentity: "foreign:process:identity",
      processStartedAt: new Date(Date.now() - 1_000).toISOString(),
      lockCreatedAt: new Date(0).toISOString(),
    });
    expect(() => acquirePortalStateLock(lockPath, { timeoutMs: 50 }))
      .toThrow("timed out acquiring portal state lock");
    expect(readPortalStateLockOwner(lockPath).token).toBe("a".repeat(64));
  });

  it("reclaims a reused PID only when process-start identity proves replacement", () => {
    const original = acquirePortalStateLock(lockPath, {
      processIdentityProbe: () => "test:original-process",
    });
    const replacement = acquirePortalStateLock(lockPath, {
      timeoutMs: 250,
      processIdentityProbe: () => "test:replacement-process",
    });
    expect(replacement.token).not.toBe(original.token);
    expect(readPortalStateLockOwner(lockPath).token).toBe(replacement.token);
    releasePortalStateLock(lockPath, replacement);
  });

  it("never reclaims a PID whose process-start identity still matches", () => {
    const owner = acquirePortalStateLock(lockPath, {
      processIdentityProbe: () => "test:same-process",
    });
    expect(() => acquirePortalStateLock(lockPath, {
      timeoutMs: 50,
      processIdentityProbe: () => "test:same-process",
    })).toThrow("timed out acquiring portal state lock");
    expect(readPortalStateLockOwner(lockPath).token).toBe(owner.token);
    releasePortalStateLock(lockPath, owner);
  });

  it("keeps permission-denied owners non-reclaimable despite an identity mismatch", () => {
    const owner = acquirePortalStateLock(lockPath, {
      processIdentityProbe: () => "test:original-process",
    });
    expect(() => acquirePortalStateLock(lockPath, {
      timeoutMs: 50,
      processIdentityProbe: () => "test:replacement-process",
      processLivenessProbe: () => "denied",
    })).toThrow("timed out acquiring portal state lock");
    expect(readPortalStateLockOwner(lockPath).token).toBe(owner.token);
    releasePortalStateLock(lockPath, owner);
  });

  it("derives a stable process identity across caller timezone and locale changes", () => {
    const prior = { TZ: process.env.TZ, LC_ALL: process.env.LC_ALL, LANG: process.env.LANG };
    try {
      process.env.TZ = "Pacific/Honolulu";
      process.env.LC_ALL = "C";
      process.env.LANG = "C";
      const first = processStartIdentity(process.pid);
      process.env.TZ = "Asia/Tokyo";
      const second = processStartIdentity(process.pid);
      expect(first).toBeTruthy();
      expect(second).toBe(first);
    } finally {
      if (prior.TZ === undefined) delete process.env.TZ; else process.env.TZ = prior.TZ;
      if (prior.LC_ALL === undefined) delete process.env.LC_ALL; else process.env.LC_ALL = prior.LC_ALL;
      if (prior.LANG === undefined) delete process.env.LANG; else process.env.LANG = prior.LANG;
    }
  });

  it("does not let a stale release remove a successor lock", () => {
    const first = acquirePortalStateLock(lockPath);
    releasePortalStateLock(lockPath, first);
    const successor = acquirePortalStateLock(lockPath);
    expect(() => releasePortalStateLock(lockPath, first)).toThrow("portal state lock release token mismatch");
    expect(readPortalStateLockOwner(lockPath).token).toBe(successor.token);
    releasePortalStateLock(lockPath, successor);
  });

  it("serializes simultaneous reclaimers and retains every process mutation", async () => {
    const dead = nodeChild(`
      const { acquirePortalStateLock } = await import(process.argv[1]);
      acquirePortalStateLock(process.argv[2]);
    `, lockPath);
    expect((await waitForExit(dead)).code).toBe(0);

    const counterPath = path.join(root, "counter.txt");
    writeFileSync(counterPath, "0\n", "utf8");
    const worker = `
      const { readFileSync, writeFileSync } = await import("node:fs");
      const { withPortalStateFileLock } = await import(process.argv[1]);
      for (let index = 0; index < 20; index += 1) {
        withPortalStateFileLock(process.argv[2], () => {
          const value = Number(readFileSync(process.argv[3], "utf8"));
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2);
          writeFileSync(process.argv[3], String(value + 1) + "\\n", "utf8");
        }, { timeoutMs: 5_000 });
      }
    `;
    const children = [nodeChild(worker, lockPath, counterPath), nodeChild(worker, lockPath, counterPath)];
    const results = await Promise.all(children.map(waitForExit));
    expect(results).toEqual([{ code: 0, stderr: "" }, { code: 0, stderr: "" }]);
    expect(Number(readFileSync(counterPath, "utf8"))).toBe(40);
    expect(existsSync(lockPath)).toBe(false);
  });

  it("keeps an old live child lock while a contender times out", async () => {
    const readyPath = path.join(root, "ready");
    const child = nodeChild(`
      const { writeFileSync } = await import("node:fs");
      const { acquirePortalStateLock, releasePortalStateLock } = await import(process.argv[1]);
      const owner = acquirePortalStateLock(process.argv[2], { now: () => 0 });
      writeFileSync(process.argv[3], "ready\\n");
      await new Promise((resolve) => setTimeout(resolve, 500));
      releasePortalStateLock(process.argv[2], owner);
    `, lockPath, readyPath);
    await waitForFile(readyPath);
    expect(() => acquirePortalStateLock(lockPath, { timeoutMs: 75 }))
      .toThrow("timed out acquiring portal state lock");
    expect((await waitForExit(child)).code).toBe(0);
  });
});
