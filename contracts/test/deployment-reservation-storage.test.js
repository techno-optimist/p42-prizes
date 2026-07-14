import assert from "node:assert/strict";
import { constants } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open as openFile,
  readdir,
  readFile,
  rename as renameFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  bindDeploymentConfigHash,
  completeManifestOutputReservation,
  createDeploymentReservationIdentity,
  deploymentReservationConfigDigest,
  manifestOutputReservationPath,
  readManifestOutputReservation,
  recordManifestOutputDeployment,
  reserveManifestOutput,
} from "../scripts/deployment-ceremony-helper.js";

const DEPLOYER = "0x0000000000000000000000000000000000000007";
const metadata = Object.freeze({
  deploymentCommit: "a".repeat(40),
  network: "baseSepolia",
  chainId: 84532,
  deployer: DEPLOYER,
});
const CONFIG_BYTES = Buffer.from('{"boards":10,"network":"baseSepolia"}\n');

function identityFor(output, trustedRoot, configBytes = CONFIG_BYTES) {
  return createDeploymentReservationIdentity(output, metadata, { trustedRoot, configBytes });
}

function broadcast(name, address, fill) {
  return { name, address, txHash: `0x${fill.repeat(64)}`, state: "broadcast", blockNumber: null };
}

function productionManifest(overrides = {}) {
  const manifest = {
    schema: "p42-prizes/deployment-manifest/v2",
    status: "pending-governance-setup",
    deploymentCommit: metadata.deploymentCommit,
    network: { name: metadata.network, chainId: metadata.chainId, explorerBaseUrl: "https://sepolia.basescan.org" },
    governance: {},
    roles: { deployer: metadata.deployer },
    parameters: {},
    contracts: {},
    governanceSetup: { status: "pending" },
    setupTransactions: [],
    problems: [],
    indexer: { startBlock: 1, finalityPolicy: {} },
    ...overrides,
  };
  return bindDeploymentConfigHash(manifest);
}

async function withDirectory(prefix, operation) {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  try {
    await operation(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function wrappedHandle(handle, kind, events, overrides = {}) {
  return {
    fd: handle.fd,
    write: overrides.write ?? ((...args) => {
      events.push("write");
      return handle.write(...args);
    }),
    read: overrides.read ?? ((...args) => handle.read(...args)),
    stat: overrides.stat ?? (() => handle.stat()),
    sync: overrides.sync ?? (() => {
      events.push(`${kind}-fsync`);
      return handle.sync();
    }),
    close: () => handle.close(),
  };
}

describe("deployment reservation durable secure storage", () => {
  it("hashes objects canonically and strict config input by exact bytes", () => {
    assert.equal(
      deploymentReservationConfigDigest({ b: 2, a: 1 }),
      deploymentReservationConfigDigest({ a: 1, b: 2 }),
    );
    assert.notEqual(
      deploymentReservationConfigDigest(Buffer.from('{"a":1}\n')),
      deploymentReservationConfigDigest(Buffer.from('{ "a": 1 }\n')),
    );
    assert.throws(
      () => deploymentReservationConfigDigest(Buffer.from('{"a":1,"a":2}\n')),
      /duplicate object key/,
    );
  });

  it("requires the complete immutable ceremony identity", async () => {
    await withDirectory("p42-reservation-identity-", async (directory) => {
      const output = join(directory, "deployment.json");
      for (const key of ["deploymentCommit", "network", "chainId", "deployer"]) {
        const incomplete = { ...metadata };
        delete incomplete[key];
        assert.throws(
          () => createDeploymentReservationIdentity(output, incomplete, { trustedRoot: directory, configBytes: CONFIG_BYTES }),
          /identity is invalid/,
        );
      }
      assert.throws(() => createDeploymentReservationIdentity(output, metadata, { configBytes: CONFIG_BYTES }), /explicit trusted root/);
      assert.throws(() => createDeploymentReservationIdentity(output, metadata, { trustedRoot: directory }), /canonical config input/);
    });
  });

  it("fsyncs the initial file and parent directory before returning", async () => {
    await withDirectory("p42-reservation-sync-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      const events = [];
      await reserveManifestOutput(identity, {
        storage: {
          async open(path, flags, mode) {
            const handle = await openFile(path, flags, mode);
            const kind = (flags & constants.O_DIRECTORY) !== 0 ? "directory" : "file";
            return wrappedHandle(handle, kind, events);
          },
        },
      });
      assert.deepEqual(events.slice(0, 4), ["write", "file-fsync", "directory-fsync"]);
      assert.equal((await stat(manifestOutputReservationPath(output))).mode & 0o777, 0o600);
    });
  });

  it("rejects truncated, symlinked, hard-linked, and non-private reservations", async () => {
    await withDirectory("p42-reservation-files-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      await reserveManifestOutput(identity);
      const reservation = manifestOutputReservationPath(output);
      const valid = await readFile(reservation);

      await writeFile(reservation, valid.subarray(0, Math.floor(valid.length / 2)), { mode: 0o600 });
      await assert.rejects(() => readManifestOutputReservation(identity), /Could not read deployment reservation/);

      await rm(reservation);
      const target = join(directory, "target.json");
      await writeFile(target, valid, { mode: 0o600 });
      await symlink(target, reservation);
      await assert.rejects(() => readManifestOutputReservation(identity), /not a regular file|Could not read/);

      await rm(reservation);
      await link(target, reservation);
      await assert.rejects(() => readManifestOutputReservation(identity), /exactly one link/);

      await rm(reservation);
      await writeFile(reservation, valid);
      await chmod(reservation, 0o644);
      await assert.rejects(() => readManifestOutputReservation(identity), /mode 0600/);

      if (typeof process.getuid === "function") {
        await chmod(reservation, 0o600);
        await assert.rejects(
          () => readManifestOutputReservation(identity, {
            storage: {
              async lstat(path) {
                const actual = await lstat(path);
                return new Proxy(actual, {
                  get(targetValue, property) {
                    return property === "uid" ? process.getuid() + 1 : Reflect.get(targetValue, property, targetValue);
                  },
                });
              },
            },
          }),
          /not owned by the current user/,
        );
      }
    });
  });

  it("rejects immutable identity tampering and unexpected schema fields", async () => {
    await withDirectory("p42-reservation-tamper-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      await reserveManifestOutput(identity);
      const reservation = manifestOutputReservationPath(output);
      const record = JSON.parse(await readFile(reservation, "utf8"));
      record.chainId = 1;
      await writeFile(reservation, `${JSON.stringify(record)}\n`, { mode: 0o600 });
      await assert.rejects(
        () => readManifestOutputReservation(identity),
        /malformed/,
      );

      record.chainId = metadata.chainId;
      record.unexpected = true;
      await writeFile(reservation, `${JSON.stringify(record)}\n`, { mode: 0o600 });
      await assert.rejects(() => readManifestOutputReservation(identity), /malformed/);
    });
  });

  it("requires the exact expected identity for reads, updates, and completion", async () => {
    await withDirectory("p42-reservation-expected-identity-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      const otherIdentity = identityFor(output, directory, Buffer.from('{"boards":9}\n'));
      await reserveManifestOutput(identity);
      await assert.rejects(() => readManifestOutputReservation(otherIdentity), /malformed/);
      await assert.rejects(
        () => recordManifestOutputDeployment(otherIdentity, "timelock", broadcast("P42MultisigTimelock", DEPLOYER, "a")),
        /malformed/,
      );
      await writeFile(output, `${JSON.stringify(productionManifest())}\n`, {
        mode: 0o600,
      });
      await assert.rejects(() => completeManifestOutputReservation(otherIdentity), /malformed|archive|identity/);
      await assert.doesNotReject(() => readManifestOutputReservation(identity));
    });
  });

  it("accepts only closed broadcast and mined deployment entry shapes", async () => {
    await withDirectory("p42-reservation-entry-schema-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      await reserveManifestOutput(identity);
      await assert.rejects(
        () => recordManifestOutputDeployment(identity, "timelock", { ...broadcast("P42MultisigTimelock", DEPLOYER, "a"), extra: true }),
        /unexpected fields/,
      );
      await recordManifestOutputDeployment(identity, "timelock", broadcast("P42MultisigTimelock", DEPLOYER, "a"));
      await assert.rejects(
        () => recordManifestOutputDeployment(identity, "timelock", {
          ...broadcast("P42MultisigTimelock", DEPLOYER, "a"), state: "mined", blockNumber: 1,
        }),
        /bytes32 hash/,
      );
      const hash = `0x${"c".repeat(64)}`;
      await recordManifestOutputDeployment(identity, "timelock", {
        ...broadcast("P42MultisigTimelock", DEPLOYER, "a"), state: "mined", blockNumber: 1,
        abiHash: hash, runtimeCodeHash: hash, deployedCodeHash: hash, constructorArgsHash: hash, constructorArgs: [],
      });
      await assert.rejects(
        () => recordManifestOutputDeployment(identity, "timelock", broadcast("P42MultisigTimelock", DEPLOYER, "a")),
        /cannot regress/,
      );
    });
  });

  it("fails closed on no-progress and ENOSPC initial writes", async () => {
    for (const failure of [
      { result: { bytesWritten: 0 }, pattern: /no progress/ },
      { error: Object.assign(new Error("disk full"), { code: "ENOSPC" }), pattern: /disk full/ },
    ]) {
      await withDirectory("p42-reservation-write-failure-", async (directory) => {
        const output = join(directory, "deployment.json");
        const identity = identityFor(output, directory);
        await assert.rejects(
          () => reserveManifestOutput(identity, {
            storage: {
              async open(path, flags, mode) {
                const handle = await openFile(path, flags, mode);
                if ((flags & constants.O_DIRECTORY) !== 0) return handle;
                return wrappedHandle(handle, "file", [], {
                  async write() {
                    if (failure.error) throw failure.error;
                    return failure.result;
                  },
                });
              },
            },
          }),
          failure.pattern,
        );
        await assert.rejects(() => readManifestOutputReservation(identity));
      });
    }
  });

  it("retries short writes until the complete durable record is stored", async () => {
    await withDirectory("p42-reservation-short-write-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      let writes = 0;
      await reserveManifestOutput(identity, {
        storage: {
          async open(path, flags, mode) {
            const handle = await openFile(path, flags, mode);
            if ((flags & constants.O_DIRECTORY) !== 0) return handle;
            return wrappedHandle(handle, "file", [], {
              async write(buffer, offset, length, position) {
                writes += 1;
                return handle.write(buffer, offset, Math.min(length, 17), position);
              },
            });
          },
        },
      });
      assert.ok(writes > 1);
      await assert.doesNotReject(() => readManifestOutputReservation(identity));
    });
  });

  it("retains the collision fence when the initial directory fsync fails", async () => {
    await withDirectory("p42-reservation-directory-fsync-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      await assert.rejects(
        () => reserveManifestOutput(identity, {
          storage: {
            async open(path, flags, mode) {
              const handle = await openFile(path, flags, mode);
              if ((flags & constants.O_DIRECTORY) === 0) return handle;
              return wrappedHandle(handle, "directory", [], {
                async sync() { throw new Error("injected directory fsync failure"); },
              });
            },
          },
        }),
        /injected directory fsync failure/,
      );
      await assert.doesNotReject(() => readManifestOutputReservation(identity));
      await assert.rejects(() => reserveManifestOutput(identity), /second deployment ceremony/);
    });
  });

  it("reports post-rename directory fsync failure while leaving a valid new generation", async () => {
    await withDirectory("p42-reservation-update-directory-fsync-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      await reserveManifestOutput(identity);
      let directorySyncs = 0;
      await assert.rejects(
        () => recordManifestOutputDeployment(identity, "timelock", {
          name: "P42MultisigTimelock", address: DEPLOYER, txHash: `0x${"a".repeat(64)}`, state: "broadcast", blockNumber: null,
        }, {
          storage: {
            async open(path, flags, mode) {
              const handle = await openFile(path, flags, mode);
              if ((flags & constants.O_DIRECTORY) === 0) return handle;
              return wrappedHandle(handle, "directory", [], {
                async sync() {
                  directorySyncs += 1;
                  if (directorySyncs === 2) throw new Error("injected directory fsync failure");
                  return handle.sync();
                },
              });
            },
          },
        }),
        /injected directory fsync failure/,
      );
      const reservation = await readManifestOutputReservation(identity);
      assert.equal(reservation.record.deployments.timelock.address, DEPLOYER);
    });
  });

  it("preserves the old reservation on update write, fsync, or rename failure", async () => {
    for (const stage of ["write", "fsync", "rename"]) {
      await withDirectory(`p42-reservation-update-${stage}-`, async (directory) => {
        const output = join(directory, "deployment.json");
        const identity = identityFor(output, directory);
        await reserveManifestOutput(identity);
        const reservation = manifestOutputReservationPath(output);
        const before = await readFile(reservation, "utf8");
        await assert.rejects(
          () => recordManifestOutputDeployment(identity, "timelock", {
            name: "P42MultisigTimelock", address: DEPLOYER, txHash: `0x${"a".repeat(64)}`, state: "broadcast", blockNumber: null,
          }, {
            storage: {
              async open(path, flags, mode) {
                const handle = await openFile(path, flags, mode);
                if (!path.includes(".tmp-")) return handle;
                return wrappedHandle(handle, "file", [], {
                  write: stage === "write" ? async () => { throw new Error("injected write failure"); } : undefined,
                  sync: stage === "fsync" ? async () => { throw new Error("injected fsync failure"); } : undefined,
                });
              },
              async rename(from, to) {
                if (stage === "rename" && from.includes(".tmp-")) throw new Error("injected rename failure");
                await renameFile(from, to);
              },
            },
          }),
          /injected/,
        );
        assert.equal(await readFile(reservation, "utf8"), before);
        assert.equal((await readdir(directory)).some((name) => name.includes(".tmp-")), false);
      });
    }
  });

  it("allows exactly one concurrent reservation creator", async () => {
    await withDirectory("p42-reservation-concurrent-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      const results = await Promise.allSettled(
        Array.from({ length: 16 }, () => reserveManifestOutput(identity)),
      );
      assert.equal(results.filter(({ status }) => status === "fulfilled").length, 1);
      assert.equal(results.filter(({ status }) => status === "rejected").length, 15);
      await assert.doesNotReject(() => readManifestOutputReservation(identity));
    });
  });

  it("serializes concurrent journal updates without losing either entry", async () => {
    await withDirectory("p42-reservation-update-race-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      await reserveManifestOutput(identity);
      await Promise.all([
        recordManifestOutputDeployment(identity, "timelock", broadcast("P42MultisigTimelock", DEPLOYER, "a")),
        recordManifestOutputDeployment(identity, "registry", broadcast(
          "P42ProblemRegistry", "0x0000000000000000000000000000000000000008", "b",
        )),
      ]);
      const reservation = await readManifestOutputReservation(identity);
      assert.equal(reservation.record.generation, 2);
      assert.equal(reservation.record.deployments.timelock.name, "P42MultisigTimelock");
      assert.equal(reservation.record.deployments.registry.name, "P42ProblemRegistry");
    });
  });

  it("retries when a lock owner releases between collision and validation", async () => {
    await withDirectory("p42-reservation-lock-handoff-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      const lockPath = `${manifestOutputReservationPath(output)}.lock`;
      let injectedCollision = false;
      await reserveManifestOutput(identity);
      await recordManifestOutputDeployment(
        identity,
        "timelock",
        broadcast("P42MultisigTimelock", DEPLOYER, "a"),
        {
          storage: {
            async open(path, flags, mode) {
              if (path === lockPath && (flags & constants.O_EXCL) !== 0 && !injectedCollision) {
                injectedCollision = true;
                const error = new Error("injected lock handoff collision");
                error.code = "EEXIST";
                throw error;
              }
              return openFile(path, flags, mode);
            },
          },
        },
      );
      assert.equal(injectedCollision, true);
      const reservation = await readManifestOutputReservation(identity);
      assert.equal(reservation.record.generation, 1);
      assert.equal(reservation.record.deployments.timelock.name, "P42MultisigTimelock");
    });
  });

  it("retries lock handoffs that replace the owner while opening or reading", async () => {
    for (const stage of ["opening", "reading"]) {
      await withDirectory(`p42-reservation-lock-${stage}-`, async (directory) => {
        const output = join(directory, "deployment.json");
        const identity = identityFor(output, directory);
        const lockPath = `${manifestOutputReservationPath(output)}.lock`;
        let injectedCollision = false;
        let replaced = false;
        let removedReplacement = false;
        await reserveManifestOutput(identity);
        await recordManifestOutputDeployment(
          identity,
          "timelock",
          broadcast("P42MultisigTimelock", DEPLOYER, "a"),
          {
            storage: {
              async open(path, flags, mode) {
                if (path === lockPath && (flags & constants.O_EXCL) !== 0 && !injectedCollision) {
                  await writeFile(lockPath, "{}\n", { mode: 0o600 });
                  injectedCollision = true;
                  const error = new Error("injected lock owner collision");
                  error.code = "EEXIST";
                  throw error;
                }
                if (path !== lockPath || (flags & constants.O_EXCL) !== 0 || replaced) {
                  return openFile(path, flags, mode);
                }
                if (stage === "opening") {
                  const replacement = `${lockPath}.replacement`;
                  await writeFile(replacement, "[]\n", { mode: 0o600 });
                  await renameFile(replacement, lockPath);
                  replaced = true;
                  const handle = await openFile(path, flags, mode);
                  return wrappedHandle(handle, "file", [], {
                    async stat() {
                      const metadata = await handle.stat();
                      await rm(lockPath, { force: true });
                      removedReplacement = true;
                      return metadata;
                    },
                  });
                }
                const handle = await openFile(path, flags, mode);
                return wrappedHandle(handle, "file", [], {
                  async read(...args) {
                    const result = await handle.read(...args);
                    if (!replaced) {
                      const replacement = `${lockPath}.replacement`;
                      await writeFile(replacement, "[]\n", { mode: 0o600 });
                      await renameFile(replacement, lockPath);
                      replaced = true;
                    }
                    return result;
                  },
                });
              },
              async lstat(path) {
                const metadata = await lstat(path);
                if (stage === "reading" && path === lockPath && replaced && !removedReplacement) {
                  await rm(lockPath, { force: true });
                  removedReplacement = true;
                }
                return metadata;
              },
            },
          },
        );
        assert.equal(injectedCollision, true);
        assert.equal(replaced, true);
        assert.equal(removedReplacement, true);
        assert.equal((await readManifestOutputReservation(identity)).record.generation, 1);
      });
    }
  });

  it("never reclaims an abandoned lock without explicit recovery", async () => {
    await withDirectory("p42-reservation-abandoned-lock-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      const lockPath = `${manifestOutputReservationPath(output)}.lock`;
      await reserveManifestOutput(identity);
      await writeFile(lockPath, `${JSON.stringify({
        schema: "p42-prizes/deployment-reservation-lock/v1",
        token: "abandoned-lock-token",
        pid: 999999999,
        hostname: hostname(),
        createdAt: new Date(0).toISOString(),
        identityDigest: identity.identityDigest,
      })}\n`, { mode: 0o600 });

      await assert.rejects(
        () => recordManifestOutputDeployment(
          identity,
          "timelock",
          broadcast("P42MultisigTimelock", DEPLOYER, "a"),
          { lockAttempts: 1 },
        ),
        /busy or abandoned; explicit recovery is required/,
      );
      assert.equal((await lstat(lockPath)).isFile(), true);
      assert.equal((await readManifestOutputReservation(identity)).record.generation, 0);
    });
  });

  it("rejects unsafe, symlinked, and replaced trusted-root ancestors", async () => {
    await withDirectory("p42-reservation-ancestors-", async (directory) => {
      const unsafe = join(directory, "unsafe");
      await mkdir(unsafe, { mode: 0o700 });
      await chmod(unsafe, 0o777);
      const unsafeIdentity = identityFor(join(unsafe, "deployment.json"), directory);
      await assert.rejects(() => reserveManifestOutput(unsafeIdentity), /ancestor is unsafe/);

      const target = join(directory, "target");
      await mkdir(target, { mode: 0o700 });
      const linked = join(directory, "linked");
      await symlink(target, linked);
      const linkedIdentity = identityFor(join(linked, "deployment.json"), directory);
      await assert.rejects(() => reserveManifestOutput(linkedIdentity), /ELOOP|ENOTDIR|symbolic link|not permitted/);

      const parent = join(directory, "parent");
      const replacement = join(directory, "replacement");
      await mkdir(parent, { mode: 0o700 });
      await mkdir(replacement, { mode: 0o700 });
      const replacedIdentity = identityFor(join(parent, "deployment.json"), directory);
      let swapped = false;
      await assert.rejects(
        () => reserveManifestOutput(replacedIdentity, {
          storage: {
            async lstat(path) {
              if (!swapped && path === parent) {
                swapped = true;
                await renameFile(parent, `${parent}-old`);
                await renameFile(replacement, parent);
              }
              return lstat(path);
            },
          },
        }),
        /ancestor was replaced/,
      );
    });
  });

  it("publishes completion evidence before retirement and recovers after a crash boundary", async () => {
    await withDirectory("p42-reservation-completion-", async (directory) => {
      const output = join(directory, "deployment.json");
      const identity = identityFor(output, directory);
      await reserveManifestOutput(identity);
      await recordManifestOutputDeployment(identity, "timelock", broadcast("P42MultisigTimelock", DEPLOYER, "a"));
      const manifestBytes = Buffer.from(`${JSON.stringify(productionManifest())}\n`);
      await writeFile(output, manifestBytes, { mode: 0o600, flag: "wx" });
      const reservationPath = manifestOutputReservationPath(output);
      const archivePath = `${output}.deployment-record.json`;

      await assert.rejects(
        () => completeManifestOutputReservation(identity, {
          storage: {
            async rm(path, options) {
              if (path.endsWith(".deployment-reservation.json")) throw new Error("simulated crash before retirement");
              return rm(path, options);
            },
          },
        }),
        /simulated crash before retirement/,
      );
      await assert.doesNotReject(() => lstat(reservationPath));
      const firstArchiveBytes = await readFile(archivePath);
      const firstArchive = JSON.parse(firstArchiveBytes);
      assert.equal(firstArchive.status, "manifest-published");
      assert.equal(firstArchive.identityDigest, identity.identityDigest);
      assert.equal(firstArchive.manifestDigest, `sha256:${await import("node:crypto").then(({ createHash }) => createHash("sha256").update(manifestBytes).digest("hex"))}`);

      await completeManifestOutputReservation(identity);
      await assert.rejects(() => lstat(reservationPath), { code: "ENOENT" });
      assert.deepEqual(await readFile(archivePath), firstArchiveBytes);

      const conflicting = { ...firstArchive, manifestDigest: `sha256:${"0".repeat(64)}` };
      await writeFile(archivePath, `${JSON.stringify(conflicting)}\n`, { mode: 0o600 });
      const conflictingBytes = await readFile(archivePath);
      await assert.rejects(() => completeManifestOutputReservation(identity), /archive conflicts/);
      assert.deepEqual(await readFile(archivePath), conflictingBytes);
    });
  });

  it("rejects production manifests with mismatched network, chain, deployer, or config binding", async () => {
    const cases = [
      ["network name", () => productionManifest({ network: { name: "base", chainId: metadata.chainId } }), /network name/],
      ["chain", () => productionManifest({ network: { name: metadata.network, chainId: 1 } }), /chainId/],
      ["deployer", () => productionManifest({ roles: { deployer: "0x0000000000000000000000000000000000000099" } }), /deployer/],
      ["config", () => ({ ...productionManifest(), deploymentConfigHash: `0x${"0".repeat(64)}` }), /deploymentConfigHash mismatch/],
    ];
    for (const [label, buildManifest, pattern] of cases) {
      await withDirectory(`p42-reservation-manifest-${label.replace(" ", "-")}-`, async (directory) => {
        const output = join(directory, "deployment.json");
        const identity = identityFor(output, directory);
        await reserveManifestOutput(identity);
        await writeFile(output, `${JSON.stringify(buildManifest())}\n`, { mode: 0o600 });
        await assert.rejects(() => completeManifestOutputReservation(identity), pattern);
        await assert.doesNotReject(() => readManifestOutputReservation(identity));
      });
    }
  });
});
