import { createHash } from "node:crypto";

const FIELDS = [
  "problem_id", "verifier_version", "verifier_image", "solution_hash", "valid",
  "improvement", "score", "reason", "recomputed_at_commit", "details",
];
const FIELD_SET = new Set(FIELDS);
const RATIONAL = /^[+-]?[0-9]+(?:\/[+-]?[0-9]+)?$/;
const HASH = /^sha256:[a-f0-9]{64}$/;

function gcd(a, b) {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) [x, y] = [y, x % y];
  return x || 1n;
}

export function canonicalRational(value) {
  if (typeof value !== "string" || !RATIONAL.test(value)) {
    throw new TypeError("rational must use the p42:v1 ASCII grammar");
  }
  const [numerator, denominator = "1"] = value.split("/");
  let n = BigInt(numerator);
  let d = BigInt(denominator);
  if (d === 0n) throw new RangeError("rational denominator must be non-zero");
  if (d < 0n) [n, d] = [-n, -d];
  const divisor = gcd(n, d);
  return `${n / divisor}/${d / divisor}`;
}

function quoteAscii(value) {
  let result = '"';
  for (const character of value) {
    const point = character.codePointAt(0);
    if (character === '"') result += '\\"';
    else if (character === "\\") result += "\\\\";
    else if (character === "\b") result += "\\b";
    else if (character === "\f") result += "\\f";
    else if (character === "\n") result += "\\n";
    else if (character === "\r") result += "\\r";
    else if (character === "\t") result += "\\t";
    else if (point >= 0x20 && point <= 0x7e) result += character;
    else if (point <= 0xffff) result += `\\u${point.toString(16).padStart(4, "0")}`;
    else {
      const offset = point - 0x10000;
      result += `\\u${(0xd800 + (offset >> 10)).toString(16)}\\u${(0xdc00 + (offset & 0x3ff)).toString(16)}`;
    }
  }
  return result + '"';
}

function compareCodePoints(left, right) {
  const a = Array.from(left, (c) => c.codePointAt(0));
  const b = Array.from(right, (c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

export function canonicalJson(value, path = "$") {
  if (value === null) return "null";
  if (typeof value === "string") return quoteAscii(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(`${path}: p42:v1 Node values require safe integers`);
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length) throw new TypeError(`${path}: sparse arrays are ambiguous`);
    return `[${value.map((item, index) => canonicalJson(item, `${path}[${index}]`)).join(",")}]`;
  }
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${path}: value is not a plain JSON object`);
  }
  const keys = Object.keys(value).sort(compareCodePoints);
  return `{${keys.map((key) => `${quoteAscii(key)}:${canonicalJson(value[key], `${path}.${key}`)}`).join(",")}}`;
}

export function verdictReport(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError("VerdictReport must be an object");
  const keys = Object.keys(value);
  const missing = FIELDS.filter((field) => !Object.hasOwn(value, field));
  const extra = keys.filter((field) => !FIELD_SET.has(field));
  if (missing.length || extra.length) throw new TypeError(`ambiguous VerdictReport fields; missing=${missing.join(",")} extra=${extra.join(",")}`);
  for (const field of ["problem_id", "verifier_version", "verifier_image", "reason", "recomputed_at_commit"]) {
    if (typeof value[field] !== "string") throw new TypeError(`${field} must be a string`);
  }
  if (typeof value.valid !== "boolean") throw new TypeError("valid must be a boolean");
  if (typeof value.solution_hash !== "string" || !HASH.test(value.solution_hash)) throw new TypeError("solution_hash must be a lowercase sha256 digest");
  if (value.details === null || typeof value.details !== "object" || Array.isArray(value.details)) throw new TypeError("details must be an object");
  return { ...value, improvement: canonicalRational(value.improvement), score: canonicalRational(value.score) };
}

export function serializeVerdictReport(value) {
  return canonicalJson(verdictReport(value));
}

export function hashVerdictReport(value) {
  return `sha256:${createHash("sha256").update(serializeVerdictReport(value), "utf8").digest("hex")}`;
}
