import assert from "node:assert/strict";
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ethers } from "ethers";

import { canonicalJson } from "./lib.mjs";
import { dispatchResolverReruns } from "./resolver-rerun-dispatcher.mjs";
import { buildResolverRerunRequest } from "./resolver-rerun-executor.mjs";

const KEY = `0x${"42".repeat(32)}`;
const SIGNER = new ethers.Wallet(KEY).address.toLowerCase();
const SHA = (digit) => `sha256:${digit.repeat(64)}`;
const HASH = (digit) => `0x${digit.repeat(64)}`;
const TEST_NOW = Date.parse("2026-07-19T12:00:00Z");

function dispatch(options) {
  return dispatchResolverReruns({ now: TEST_NOW, ...options });
}

function requestFor(boardId = "84532:2:hadamard-mini", packetDigit = "1", nonceDigit = "4",
  expiresAt = "2026-07-20T00:00:00Z") {
  const chainClaim = { chain_id: 84532, problem_id: "hadamard-mini", block_number: 10, log_index: 1 };
  const transcriptHash = SHA("9");
  const packet = {
    packet_hash: SHA(packetDigit), decision_digest: HASH("2"),
    decision: { transcriptHash: `0x${transcriptHash.slice(7)}`, challengeInstanceHash: HASH("3"),
      adapter: "0x1111111111111111111111111111111111111111", manager: "0x2222222222222222222222222222222222222222" },
  };
  const challenge = { packet_hash: packet.packet_hash, decision_digest: packet.decision_digest,
    challenge_instance_hash: packet.decision.challengeInstanceHash, orchestrator_nonce: HASH(nonceDigit),
    issued_at_utc: "2026-07-19T00:00:00Z", expires_at_utc: expiresAt };
  return buildResolverRerunRequest({ packet, challenge, boardId,
    manifestPath: "/opt/p42/deployments/test.json", manifestBytes: Buffer.from("{}\n"),
    publishedTranscript: { transcript_hash: transcriptHash, verifier: { chain_claim: chainClaim } },
    manifestRoot: "/opt/p42", requestSignerPrivateKey: KEY });
}

function fixture(boardId) {
  const root = mkdtempSync(join(tmpdir(), "p42-dispatcher-"));
  const sourceRoot = join(root, "source");
  const requestRoot = join(root, "requests");
  const journalRoot = join(root, "journal");
  const resultRoot = join(root, "results");
  for (const path of [sourceRoot, requestRoot, journalRoot, resultRoot]) mkdirSync(path, { mode: 0o700 });
  const gid = lstatSync(requestRoot).gid || 20;
  chmodSync(requestRoot, 0o750);
  mkdirSync(join(requestRoot, "2"), { mode: 0o750 });
  const request = requestFor(boardId);
  const name = `${request.packet_hash.slice(7)}-${request.orchestrator_nonce.slice(2)}.json`;
  writeFileSync(join(sourceRoot, name), `${canonicalJson(request)}\n`, { mode: 0o600 });
  const dispatchMap = { schema_version: "p42-resolver-rerun-dispatch-map/v1", request_signer: SIGNER,
    request_reader_gid: gid, submitter_gid: gid,
    boards: [{ registry_problem_id: "2", board_id: "84532:2:hadamard-mini", rerun_uid: 42002 }] };
  return { root, sourceRoot, requestRoot, journalRoot, resultRoot, request, dispatchMap,
    authorityUid: lstatSync(requestRoot).uid };
}

function unavailableResult() { throw Object.assign(new Error("missing"), { code: "ENOENT" }); }

test("dispatcher installs exact signer bytes and starts only its canonical mapped unit", () => {
  const value = fixture();
  const calls = [];
  try {
    const reports = dispatch({ ...value, resultReader: unavailableResult,
      manager: { status(unit) { calls.push(["status", unit]); return { LoadState: "loaded", ActiveState: "inactive" }; },
        start(unit) { calls.push(["start", unit]); }, resetFailed() { assert.fail("unexpected reset"); } } });
    assert.equal(reports[0].status, "dispatched");
    assert.deepEqual(calls, [["status", "p42-resolver-rerun@2.service"], ["start", "p42-resolver-rerun@2.service"]]);
    const installed = readFileSync(join(value.requestRoot, "2", "request.json"));
    assert.equal(JSON.parse(installed).request_hash, value.request.request_hash);
    assert.equal(installed.toString(), `${canonicalJson(value.request)}\n`);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test("dispatcher resumes a crash after systemctl start without starting twice", () => {
  const value = fixture();
  let starts = 0;
  let active = false;
  const manager = { status() { return { LoadState: "loaded", ActiveState: active ? "active" : "inactive" }; },
    start() { starts += 1; active = true; }, resetFailed() {} };
  try {
    assert.throws(() => dispatch({ ...value, manager, resultReader: unavailableResult,
      crash(point) { if (point === "after-systemctl-start") throw new Error("power loss"); } }), /power loss/);
    const reports = dispatch({ ...value, manager, resultReader: unavailableResult });
    assert.equal(starts, 1);
    assert.equal(reports[0].status, "dispatched");
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test("dispatcher rejects cross-board substitution and signer-spool symlinks", () => {
  const cross = fixture("84532:3:other");
  try {
    assert.throws(() => dispatch({ ...cross, resultReader: unavailableResult, manager: {} }),
      /board is not in the protected dispatch map/);
  } finally { rmSync(cross.root, { recursive: true, force: true }); }
  const linked = fixture();
  try {
    const name = `${linked.request.packet_hash.slice(7)}-${linked.request.orchestrator_nonce.slice(2)}.json`;
    const path = join(linked.sourceRoot, name);
    const target = join(linked.root, "target.json");
    writeFileSync(target, readFileSync(path), { mode: 0o600 }); rmSync(path); symlinkSync(target, path);
    assert.throws(() => dispatch({ ...linked, resultReader: unavailableResult, manager: {} }),
      /spool authority mismatch/);
  } finally { rmSync(linked.root, { recursive: true, force: true }); }
});

test("systemd boundary keeps dispatch root-owned and rerun request state read-only", () => {
  const root = new URL("..", import.meta.url).pathname;
  const dispatcher = readFileSync(join(root, "deployments", "p42-resolver-rerun-dispatcher.service.example"), "utf8");
  const rerun = readFileSync(join(root, "deployments", "p42-resolver-rerun@.service.example"), "utf8");
  const path = readFileSync(join(root, "deployments", "p42-resolver-rerun-dispatcher.path.example"), "utf8");
  const verifier = readFileSync(join(root, "deployments", "p42-verifier-executor.service.example"), "utf8");
  const rerunSource = readFileSync(join(root, "agent", "resolver-rerun-executor.mjs"), "utf8");
  const users = readFileSync(join(root, "deployments", "p42-runtime.sysusers.example"), "utf8");
  assert.doesNotMatch(dispatcher, /^User=/m);
  assert.match(dispatcher, /^CapabilityBoundingSet=CAP_DAC_READ_SEARCH$/m);
  assert.match(dispatcher, /^AmbientCapabilities=CAP_DAC_READ_SEARCH$/m);
  assert.match(dispatcher, /ReadOnlyPaths=.*resolver-quorum-signatures\/rerun-requests.*resolver-rerun-results/);
  assert.match(dispatcher, /ReadWritePaths=\/var\/lib\/p42\/resolver-rerun-requests \/var\/lib\/p42\/resolver-rerun-dispatcher/);
  assert.match(path, /^PathChanged=\/var\/lib\/p42\/resolver-quorum-signatures\/rerun-requests$/m);
  assert.match(path, /^PathChanged=\/var\/lib\/p42\/resolver-rerun-results$/m);
  assert.match(rerun, /--request \/var\/lib\/p42\/resolver-rerun-requests\/%i\/request\.json/);
  assert.match(rerun, /ReadOnlyPaths=.*resolver-rerun-requests\/%i/);
  assert.doesNotMatch(rerun, /ReadWritePaths=.*resolver-rerun-requests/);
  assert.doesNotMatch(rerun, /attestor-key|executor-key/);
  assert.match(verifier, /^LoadCredential=resolver-rerun-attestor-key:/m);
  assert.match(verifier, /--resolver-rerun-attestor-key \$\{CREDENTIALS_DIRECTORY\}\/resolver-rerun-attestor-key/);
  assert.doesNotMatch(rerunSource, /private_key|createPrivateKey|signEd25519/);
  assert.match(users, /^g p42-resolver-rerun-requests -$/m);
  assert.match(users, /^m p42-resolver p42-verifier-submitters$/m);
  assert.match(users, /^m p42-resolver-rerun-2 p42-resolver-rerun-requests$/m);
  assert.match(users, /^m p42-verifier-executor p42-resolver-rerun-requests$/m);
});

for (const crashPoint of [null, "after-rotation-journal", "after-install"]) {
  test(`dispatcher safely rotates two sequential requests for one board${crashPoint ? ` across ${crashPoint}` : ""}`, () => {
    const value = fixture();
    let active = false;
    let firstCompleted = false;
    let starts = 0;
    const manager = { status() { return { LoadState: "loaded", ActiveState: active ? "active" : "inactive" }; },
      start() { starts += 1; active = true; }, resetFailed() {} };
    const resultReader = (path) => {
      if (firstCompleted && path.includes(value.request.packet_hash.slice(7))) return {};
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    };
    try {
      dispatch({ ...value, manager, resultReader });
      active = false; firstCompleted = true;
      const second = requestFor("84532:2:hadamard-mini", "5", "6");
      const secondName = `${second.packet_hash.slice(7)}-${second.orchestrator_nonce.slice(2)}.json`;
      writeFileSync(join(value.sourceRoot, secondName), `${canonicalJson(second)}\n`, { mode: 0o600 });
      if (crashPoint) {
        assert.throws(() => dispatch({ ...value, manager, resultReader,
          crash(point, request) { if (point === crashPoint && request.request_hash === second.request_hash) throw new Error("rotation crash"); } }),
        /rotation crash/);
      }
      const reports = dispatch({ ...value, manager, resultReader });
      assert.equal(starts, 2);
      assert.ok(reports.some((report) => report.request_hash === second.request_hash && report.status === "dispatched"));
      assert.equal(readFileSync(join(value.requestRoot, "2", "request.json"), "utf8"), `${canonicalJson(second)}\n`);
    } finally { rmSync(value.root, { recursive: true, force: true }); }
  });
}

test("expiry during an active rerun preserves the busy slot before a later request rotates", () => {
  const value = fixture();
  let active = false;
  let firstCompleted = false;
  let starts = 0;
  const manager = { status() { return { LoadState: "loaded", ActiveState: active ? "active" : "inactive" }; },
    start() { starts += 1; active = true; }, resetFailed() {} };
  const resultReader = (path) => {
    if (firstCompleted && path.includes(value.request.packet_hash.slice(7))) return {};
    throw Object.assign(new Error("missing"), { code: "ENOENT" });
  };
  try {
    dispatch({ ...value, manager, resultReader });
    const second = requestFor("84532:2:hadamard-mini", "5", "6", "2026-07-22T00:00:00Z");
    const secondName = `${second.packet_hash.slice(7)}-${second.orchestrator_nonce.slice(2)}.json`;
    writeFileSync(join(value.sourceRoot, secondName), `${canonicalJson(second)}\n`, { mode: 0o600 });
    const whileActive = dispatch({ ...value, manager, resultReader, now: Date.parse("2026-07-21T00:00:00Z") });
    assert.equal(whileActive.length, 1);
    assert.equal(whileActive[0].request_hash, value.request.request_hash);
    assert.equal(whileActive[0].status, "dispatched");
    assert.equal(readFileSync(join(value.requestRoot, "2", "request.json"), "utf8"), `${canonicalJson(value.request)}\n`);
    active = false; firstCompleted = true;
    const resumed = dispatch({ ...value, manager, resultReader, now: Date.parse("2026-07-21T00:00:00Z") });
    assert.ok(resumed.some((report) => report.request_hash === second.request_hash && report.status === "dispatched"));
    assert.equal(starts, 2);
    assert.equal(readFileSync(join(value.requestRoot, "2", "request.json"), "utf8"), `${canonicalJson(second)}\n`);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});
