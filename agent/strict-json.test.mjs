import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { parseStrictJsonBytes, parseStrictJsonText, readStrictJsonFile } from "./strict-json.mjs";

const REJECTION_FIXTURES = [
  ['{"a":1,"a":2}', /duplicate object key "a"/],
  ['{"a":{"x":1,"x":2}}', /duplicate object key "x"/],
  ['{"a":1,"\\u0061":2}', /duplicate object key "a"/],
  ['{"__proto__":1}', /forbidden object key/],
  ['{"prototype":1}', /forbidden object key/],
  ['{"constructor":1}', /forbidden object key/],
  ["9007199254740993", /safe integer range/],
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

  it("enforces canonical bytes and trailing-newline modes", () => {
    assert.deepEqual(parseStrictJsonText('{"a":1,"b":2}', { canonical: true }), { a: 1, b: 2 });
    assert.throws(() => parseStrictJsonText('{"b":2,"a":1}', { canonicalBytes: true }), /not canonical/);
    assert.throws(() => parseStrictJsonText('{ "a": 1 }', { canonical: true }), /not canonical/);
    assert.equal(parseStrictJsonText("null\n", { canonical: true, trailingNewline: "require" }), null);
    assert.throws(() => parseStrictJsonText("null", { trailingNewline: true }), /must end/);
    assert.throws(() => parseStrictJsonText("null\n", { trailingNewline: false }), /must not end/);
    assert.throws(() => parseStrictJsonText("null\r\n", { canonical: true }), /exactly one LF/);
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
});
