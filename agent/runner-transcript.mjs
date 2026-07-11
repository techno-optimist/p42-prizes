import { sha256Canonical } from "./lib.mjs";
import { readStrictJsonFileSync } from "./strict-json.mjs";

const IMMUTABLE_JSON_LIMITS = Object.freeze({
  maxBytes: 4 * 1024 * 1024,
  maxDepth: 64,
  canonicalBytes: true,
  trailingNewline: "require",
});

export function verifyRunnerTranscript(path, expectedHash) {
  if (typeof expectedHash !== "string" || !/^sha256:[0-9a-f]{64}$/.test(expectedHash)) {
    throw new Error(`queue transcript hash is missing or malformed: ${path}`);
  }
  const transcript = readStrictJsonFileSync(path, IMMUTABLE_JSON_LIMITS);
  const embeddedHash = transcript.transcript_hash;
  const unhashed = { ...transcript };
  delete unhashed.transcript_hash;
  if (sha256Canonical(unhashed) !== embeddedHash) {
    throw new Error(`transcript self-hash mismatch: ${path}`);
  }
  if (embeddedHash !== expectedHash) {
    throw new Error(`queue transcript hash mismatch: ${path}`);
  }
  const candidate = transcript.verifier?.challenge_candidate;
  if (!candidate) return { transcript, candidate: null };
  const candidateHash = candidate.candidate_hash;
  const unsigned = { ...candidate };
  delete unsigned.candidate_hash;
  if (sha256Canonical(unsigned) !== candidateHash) {
    throw new Error(`candidate self-hash mismatch: ${path}`);
  }
  return { transcript, candidate };
}
