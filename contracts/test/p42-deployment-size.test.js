import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const EIP_170_LIMIT_BYTES = 24_576;
const PRODUCTION_CONTRACTS = [
  ["P42AgentWallet", "artifacts/src/P42AgentWallet.sol/P42AgentWallet.json"],
  ["P42BountyPool", "artifacts/src/P42BountyPool.sol/P42BountyPool.json"],
  ["P42ChallengeManager", "artifacts/src/P42ChallengeManager.sol/P42ChallengeManager.json"],
  ["P42MultisigTimelock", "artifacts/src/P42MultisigTimelock.sol/P42MultisigTimelock.json"],
  ["P42PayoutLedger", "artifacts/src/P42PayoutLedger.sol/P42PayoutLedger.json"],
  ["P42ProblemRegistry", "artifacts/src/P42ProblemRegistry.sol/P42ProblemRegistry.json"],
  ["P42SubmissionManager", "artifacts/src/P42SubmissionManager.sol/P42SubmissionManager.json"],
];

describe("P42 deployment bytecode", function () {
  for (const [contractName, artifactPath] of PRODUCTION_CONTRACTS) {
    it(`${contractName} remains deployable under EIP-170`, async function () {
      const artifact = JSON.parse(await readFile(artifactPath, "utf8"));
      const deployedBytes = (artifact.deployedBytecode.length - 2) / 2;

      assert.ok(deployedBytes > 0, `${contractName} has no deployed bytecode`);
      assert.ok(
        deployedBytes <= EIP_170_LIMIT_BYTES,
        `${contractName} is ${deployedBytes} bytes, above the ${EIP_170_LIMIT_BYTES}-byte EIP-170 limit`,
      );
    });
  }
});
