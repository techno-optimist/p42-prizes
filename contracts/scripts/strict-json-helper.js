import {
  readStrictJsonFile,
  readStrictJsonFileWithBytes,
  readStrictJsonFileSync,
  readStrictJsonFileSyncWithBytes,
} from "p42-agent/strict-json.mjs";

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

export function readContractsConfigJsonWithBytes(path, options = {}) {
  return readStrictJsonFileWithBytes(path, { ...CONFIG_LIMITS, ...options });
}

export function readContractsConfigJsonSync(path) {
  return readStrictJsonFileSync(path, CONFIG_LIMITS);
}

export function readContractsConfigJsonSyncWithBytes(path, options = {}) {
  return readStrictJsonFileSyncWithBytes(path, { ...CONFIG_LIMITS, ...options });
}

export function readContractsArtifactJson(path) {
  return readStrictJsonFile(path, ARTIFACT_LIMITS);
}

export function readContractsArtifactJsonWithBytes(path, options = {}) {
  return readStrictJsonFileWithBytes(path, { ...ARTIFACT_LIMITS, ...options });
}

export function readContractsArtifactJsonTrustedPublic(path, trustedRoot) {
  return readStrictJsonFile(path, { ...ARTIFACT_LIMITS, trustedRoot, publicFile: true });
}

export function readContractsArtifactJsonSyncWithBytes(path, options = {}) {
  return readStrictJsonFileSyncWithBytes(path, { ...ARTIFACT_LIMITS, ...options });
}
