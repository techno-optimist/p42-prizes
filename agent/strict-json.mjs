import { constants } from "node:fs";
import { open } from "node:fs/promises";

const DEFAULT_MAX_BYTES = 1024 * 1024;
const DEFAULT_MAX_DEPTH = 128;
const FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function optionsWithDefaults(options = {}) {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new TypeError("maxBytes must be a non-negative safe integer");
  }
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  if (!Number.isSafeInteger(maxDepth) || maxDepth < 0) {
    throw new TypeError("maxDepth must be a non-negative safe integer");
  }
  const canonical = options.canonicalBytes ?? options.canonical ?? false;
  let trailingNewline = options.trailingNewline ?? options.trailingNewlinePolicy ?? "allow";
  if (trailingNewline === true) trailingNewline = "require";
  if (trailingNewline === false) trailingNewline = "forbid";
  if (!new Set(["allow", "require", "forbid"]).has(trailingNewline)) {
    throw new TypeError('trailingNewline must be "allow", "require", or "forbid"');
  }
  return { maxBytes, maxDepth, canonical: Boolean(canonical), trailingNewline };
}

function normalizedDecimal(lexeme) {
  let text = lexeme;
  let negative = false;
  if (text[0] === "-") { negative = true; text = text.slice(1); }
  const [mantissa, exponentText = "0"] = text.toLowerCase().split("e");
  const point = mantissa.indexOf(".");
  const fractionDigits = point === -1 ? 0 : mantissa.length - point - 1;
  let digits = mantissa.replace(".", "").replace(/^0+/, "");
  if (!digits) return { negative: false, digits: "0", power: 0 };
  let trailingZeros = 0;
  while (digits.endsWith("0")) { digits = digits.slice(0, -1); trailingZeros++; }
  return { negative, digits, power: Number(exponentText) - fractionDigits + trailingZeros };
}

function sameExactDecimal(left, right) {
  const a = normalizedDecimal(left);
  const b = normalizedDecimal(right);
  return a.negative === b.negative && a.digits === b.digits && a.power === b.power;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

class Parser {
  constructor(text, maxDepth) {
    this.text = text;
    this.index = 0;
    this.maxDepth = maxDepth;
  }

  error(message) {
    throw new SyntaxError(`${message} at character ${this.index}`);
  }

  whitespace() {
    while (this.index < this.text.length && /[\x20\x09\x0a\x0d]/.test(this.text[this.index])) this.index++;
  }

  value(depth = 0) {
    this.whitespace();
    const c = this.text[this.index];
    if (c === "{" || c === "[") {
      if (depth >= this.maxDepth) this.error(`JSON exceeds maxDepth (${this.maxDepth})`);
      return c === "{" ? this.object(depth + 1) : this.array(depth + 1);
    }
    if (c === '"') return this.string();
    if (c === "t") return this.literal("true", true);
    if (c === "f") return this.literal("false", false);
    if (c === "n") return this.literal("null", null);
    if (c === "-" || (c >= "0" && c <= "9")) return this.number();
    this.error("expected a JSON value");
  }

  literal(token, value) {
    if (!this.text.startsWith(token, this.index)) this.error(`expected ${token}`);
    this.index += token.length;
    return value;
  }

  string() {
    this.index++;
    let result = "";
    while (this.index < this.text.length) {
      const c = this.text[this.index++];
      if (c === '"') return result;
      if (c === "\\") {
        if (this.index >= this.text.length) this.error("unterminated escape sequence");
        const escape = this.text[this.index++];
        const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (Object.hasOwn(simple, escape)) {
          result += simple[escape];
        } else if (escape === "u") {
          const hex = this.text.slice(this.index, this.index + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.error("invalid Unicode escape");
          result += String.fromCharCode(Number.parseInt(hex, 16));
          this.index += 4;
        } else {
          this.error("invalid escape sequence");
        }
      } else {
        if (c.charCodeAt(0) <= 0x1f) this.error("unescaped control character in string");
        result += c;
      }
    }
    this.error("unterminated string");
  }

  number() {
    const start = this.index;
    if (this.text[this.index] === "-") this.index++;
    if (this.text[this.index] === "0") {
      this.index++;
      if (/[0-9]/.test(this.text[this.index] ?? "")) this.error("leading zero in number");
    } else if (/[1-9]/.test(this.text[this.index] ?? "")) {
      while (/[0-9]/.test(this.text[this.index] ?? "")) this.index++;
    } else {
      this.error("invalid number");
    }
    if (this.text[this.index] === ".") {
      this.index++;
      if (!/[0-9]/.test(this.text[this.index] ?? "")) this.error("fraction requires a digit");
      while (/[0-9]/.test(this.text[this.index] ?? "")) this.index++;
    }
    if (this.text[this.index] === "e" || this.text[this.index] === "E") {
      this.index++;
      if (this.text[this.index] === "+" || this.text[this.index] === "-") this.index++;
      if (!/[0-9]/.test(this.text[this.index] ?? "")) this.error("exponent requires a digit");
      while (/[0-9]/.test(this.text[this.index] ?? "")) this.index++;
    }
    const lexeme = this.text.slice(start, this.index);
    const value = Number(lexeme);
    if (!Number.isFinite(value)) this.error("number is not finite");
    if (Math.abs(value) > Number.MAX_SAFE_INTEGER) this.error("number is outside the safe numeric range");
    if (!sameExactDecimal(lexeme, JSON.stringify(value))) this.error("number cannot be represented exactly");
    return value;
  }

  array(depth) {
    this.index++;
    const result = [];
    this.whitespace();
    if (this.text[this.index] === "]") { this.index++; return result; }
    while (true) {
      result.push(this.value(depth));
      this.whitespace();
      if (this.text[this.index] === "]") { this.index++; return result; }
      if (this.text[this.index++] !== ",") this.error("expected ',' or ']' in array");
    }
  }

  object(depth) {
    this.index++;
    const entries = [];
    const keys = new Set();
    this.whitespace();
    if (this.text[this.index] === "}") { this.index++; return {}; }
    while (true) {
      this.whitespace();
      if (this.text[this.index] !== '"') this.error("object key must be a string");
      const key = this.string();
      if (FORBIDDEN_KEYS.has(key)) this.error(`forbidden object key ${JSON.stringify(key)}`);
      if (keys.has(key)) this.error(`duplicate object key ${JSON.stringify(key)}`);
      keys.add(key);
      this.whitespace();
      if (this.text[this.index++] !== ":") this.error("expected ':' after object key");
      entries.push([key, this.value(depth)]);
      this.whitespace();
      if (this.text[this.index] === "}") {
        this.index++;
        return Object.fromEntries(entries);
      }
      if (this.text[this.index++] !== ",") this.error("expected ',' or '}' in object");
    }
  }
}

function parseText(text, maxDepth) {
  const parser = new Parser(text, maxDepth);
  const value = parser.value();
  parser.whitespace();
  if (parser.index !== text.length) parser.error("unexpected trailing data");
  return value;
}

function checkPolicies(text, value, { canonical, trailingNewline }) {
  const trailingWhitespace = /[\x20\x09\x0a\x0d]*$/.exec(text)[0];
  const hasNewline = trailingWhitespace.includes("\n") || trailingWhitespace.includes("\r");
  if (trailingNewline === "require" && trailingWhitespace !== "\n") {
    throw new SyntaxError("JSON must end with exactly one LF trailing newline");
  }
  if (trailingNewline === "forbid" && hasNewline) throw new SyntaxError("JSON must not end with a trailing newline");
  if (canonical) {
    const expected = canonicalJson(value) + (hasNewline ? "\n" : "");
    if (text !== expected) throw new SyntaxError("JSON bytes are not canonical");
  }
}

export function parseStrictJsonText(text, options = {}) {
  if (typeof text !== "string") throw new TypeError("JSON text must be a string");
  const normalized = optionsWithDefaults(options);
  if (Buffer.byteLength(text, "utf8") > normalized.maxBytes) throw new RangeError(`JSON exceeds maxBytes (${normalized.maxBytes})`);
  const value = parseText(text, normalized.maxDepth);
  checkPolicies(text, value, normalized);
  return value;
}

export function parseStrictJsonBytes(bytes, options = {}) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("JSON bytes must be a Uint8Array");
  const normalized = optionsWithDefaults(options);
  if (bytes.byteLength > normalized.maxBytes) throw new RangeError(`JSON exceeds maxBytes (${normalized.maxBytes})`);
  let text;
  try { text = UTF8.decode(bytes); } catch (error) { throw new SyntaxError(`JSON is not valid UTF-8: ${error.message}`); }
  return parseStrictJsonText(text, normalized);
}

export async function readStrictJsonFile(path, options = {}) {
  const normalized = optionsWithDefaults(options);
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) {
    throw new Error("secure JSON file reads require platform O_NOFOLLOW support");
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new TypeError("JSON path must refer to a regular file");
    if (stat.size > normalized.maxBytes) throw new RangeError(`JSON exceeds maxBytes (${normalized.maxBytes})`);
    const chunks = [];
    let total = 0;
    while (true) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, normalized.maxBytes - total + 1));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > normalized.maxBytes) throw new RangeError(`JSON exceeds maxBytes (${normalized.maxBytes})`);
      chunks.push(chunk.subarray(0, bytesRead));
    }
    return parseStrictJsonBytes(Buffer.concat(chunks, total), normalized);
  } finally {
    await handle.close();
  }
}
