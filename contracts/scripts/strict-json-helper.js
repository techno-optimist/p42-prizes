import {
  readStrictJsonFile,
  readStrictJsonFileWithBytes,
  readStrictJsonFileSync,
  readStrictJsonFileSyncWithBytes,
} from "../../agent/strict-json.mjs";

const CONFIG_LIMITS = Object.freeze({
  maxBytes: 1024 * 1024,
  maxDepth: 64,
  trailingNewline: "allow",
});

const ARTIFACT_LIMITS = Object.freeze({
  maxBytes: 8 * 1024 * 1024,
  maxDepth: 128,
  trailingNewline: "require",
});

export function readContractsConfigJson(path) {
  return readStrictJsonFile(path, CONFIG_LIMITS);
}

export function readContractsConfigJsonSync(path) {
  return readStrictJsonFileSync(path, CONFIG_LIMITS);
}

export function readContractsArtifactJson(path) {
  return readStrictJsonFile(path, ARTIFACT_LIMITS);
}

export function readContractsArtifactJsonWithBytes(path, options = {}) {
  return readStrictJsonFileWithBytes(path, { ...ARTIFACT_LIMITS, ...options });
}

export function readContractsArtifactJsonSyncWithBytes(path, options = {}) {
  return readStrictJsonFileSyncWithBytes(path, { ...ARTIFACT_LIMITS, ...options });
}
