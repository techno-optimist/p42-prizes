import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { parseStrictJsonBytes, parseStrictJsonText, readStrictJsonFile, readStrictJsonFileSync } from "./strict-json.mjs";

const REJECTION_FIXTURES = [
  ['{"a":1,"a":2}', /duplicate object key "a"/],
  ['{"a":{"x":1,"x":2}}', /duplicate object key "x"/],
  ['{"a":1,"\\u0061":2}', /duplicate object key "a"/],
  ['{"__proto__":1}', /forbidden object key/],
  ['{"prototype":1}', /forbidden object key/],
  ['{"constructor":1}', /forbidden object key/],
  ["9007199254740993", /safe numeric range/],
  ["9007199254740993.0", /safe numeric range/],
  ["9007199254740993e0", /safe numeric range/],
  ["9007199254740992.5", /safe numeric range/],
  ["1.0000000000000001", /decimal-round-trip stable/],
  ["1e-400", /decimal-round-trip stable/],
  ["NaN", /expected a JSON value/],
  ["Infinity", /expected a JSON value/],
  ["01", /leading zero/],
  ["1e999", /not finite/],
];

describe("strict JSON parser", () => {
  it("parses JSON values without dependencies", () => {
    assert.deepEqual(parseStrictJsonText('{"ok":[true,false,null,-12.5e2],"s":"x\\n"}'), {
      ok: [true, false, null, -1250], s: "x\n",
    });
  });

  it("accepts decimal-round-trip-stable finite numbers within the safe numeric range", () => {
    for (const [lexeme, expected] of [
      ["9007199254740991", 9007199254740991],
      ["-9007199254740991.0", -9007199254740991],
      ["0.1", 0.1],
      ["1.2300e+2", 123],
      ["5e-324", 5e-324],
    ]) assert.equal(parseStrictJsonText(lexeme), expected, lexeme);
  });

  it("rejects representative dangerous lexemes before object construction", () => {
    for (const [fixture, expected] of REJECTION_FIXTURES) {
      assert.throws(() => parseStrictJsonText(fixture), expected, fixture);
    }
  });

  it("rejects invalid UTF-8 and oversized text or bytes", () => {
    assert.throws(() => parseStrictJsonBytes(Uint8Array.of(0xff)), /valid UTF-8/);
    assert.throws(() => parseStrictJsonBytes(Buffer.from("efbbbf6e756c6c", "hex")), /expected a JSON value/);
    assert.throws(() => parseStrictJsonText("null", { maxBytes: 3 }), /maxBytes/);
    assert.throws(() => parseStrictJsonBytes(Buffer.from("null"), { maxBytes: 3 }), /maxBytes/);
  });

  it("rejects excessive nesting before the JavaScript call stack is approached", () => {
    assert.deepEqual(parseStrictJsonText('[[{"ok":true}]]', { maxDepth: 3 }), [[{ ok: true }]]);
    assert.throws(() => parseStrictJsonText('[[{"no":true}]]', { maxDepth: 2 }), /maxDepth \(2\)/);
    assert.throws(() => parseStrictJsonText("[".repeat(10_000) + "]".repeat(10_000), { maxDepth: 64 }), /maxDepth \(64\)/);
    assert.throws(() => parseStrictJsonText("[]", { maxDepth: 0 }), /maxDepth \(0\)/);
    assert.throws(() => parseStrictJsonText("null", { maxDepth: -1 }), /maxDepth/);
  });

  it("enforces canonical bytes and trailing-newline modes", () => {
    assert.deepEqual(parseStrictJsonText('{"a":1,"b":2}', { canonical: true }), { a: 1, b: 2 });
    assert.throws(() => parseStrictJsonText('{"b":2,"a":1}', { canonicalBytes: true }), /not canonical/);
    assert.throws(() => parseStrictJsonText('{ "a": 1 }', { canonical: true }), /not canonical/);
    assert.equal(parseStrictJsonText("null\n", { canonical: true, trailingNewline: "require" }), null);
    assert.throws(() => parseStrictJsonText("null", { trailingNewline: true }), /must end/);
    assert.throws(() => parseStrictJsonText("null\n", { trailingNewline: false }), /must not end/);
    assert.throws(() => parseStrictJsonText("null\r\n", { canonical: true }), /not canonical/);
    assert.throws(() => parseStrictJsonText("null\n  ", { trailingNewline: "forbid" }), /must not/);
    assert.throws(() => parseStrictJsonText("null\r  ", { trailingNewline: "forbid" }), /must not/);
    assert.throws(() => parseStrictJsonText("null\n  ", { trailingNewline: "require" }), /exactly one LF/);
    assert.throws(() => parseStrictJsonText("null  \n", { trailingNewline: "require" }), /exactly one LF/);
  });
});

describe("strict JSON file reader", () => {
  it("reads a bounded regular file and rejects oversized files", async () => {
    const root = await mkdtemp(join(tmpdir(), "p42-strict-json-"));
    try {
      const path = join(root, "value.json");
      await writeFile(path, '{"value":42}\n');
      assert.deepEqual(await readStrictJsonFile(path, { trailingNewline: "require" }), { value: 42 });
      await assert.rejects(readStrictJsonFile(path, { maxBytes: 4 }), /maxBytes/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects symlinks, FIFOs, and directories", async () => {
    const root = await mkdtemp(join(tmpdir(), "p42-strict-json-special-"));
    try {
      const file = join(root, "file.json");
      const link = join(root, "link.json");
      const directory = join(root, "directory");
      const fifo = join(root, "fifo");
      await writeFile(file, "null");
      await symlink(file, link);
      await mkdir(directory);
      execFileSync("mkfifo", [fifo]);
      await assert.rejects(readStrictJsonFile(link));
      await assert.rejects(readStrictJsonFile(directory), /regular file/);
      await assert.rejects(readStrictJsonFile(fifo), /regular file/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("applies the same single-FD limits and canonical policy synchronously", async () => {
    const root = await mkdtemp(join(tmpdir(), "p42-strict-json-sync-"));
    try {
      const file = join(root, "immutable.json");
      const link = join(root, "link.json");
      await writeFile(file, '{"family":"journal"}\n');
      await symlink(file, link);
      assert.deepEqual(readStrictJsonFileSync(file, {
        maxBytes: 64, maxDepth: 4, canonicalBytes: true, trailingNewline: "require",
      }), { family: "journal" });
      assert.throws(() => readStrictJsonFileSync(link));
      assert.throws(() => readStrictJsonFileSync(file, { maxBytes: 4 }), /maxBytes/);
      await writeFile(file, '{"outer":{"constructor":1}}\n');
      assert.throws(() => readStrictJsonFileSync(file), /forbidden object key/);
      await writeFile(file, '{"outer":{"x":1,"x":2}}\n');
      assert.throws(() => readStrictJsonFileSync(file), /duplicate object key/);
      await writeFile(file, '{ "family": "journal" }\n');
      assert.throws(() => readStrictJsonFileSync(file, {
        canonicalBytes: true, trailingNewline: "require",
      }), /not canonical/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
