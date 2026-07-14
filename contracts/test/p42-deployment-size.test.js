import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const EIP_170_LIMIT_BYTES = 24_576;
const PRODUCTION_CONTRACTS = [
  ["P42AgentWallet", "artifacts/src/P42AgentWallet.sol/P42AgentWallet.json"],
  ["P42BountyPool", "artifacts/src/P42BountyPool.sol/P42BountyPool.json"],
  ["P42ChallengeManager", "artifacts/src/P42ChallengeManager.sol/P42ChallengeManager.json"],
  ["P42ChallengeManagerFactory", "artifacts/src/P42ChallengeManagerFactory.sol/P42ChallengeManagerFactory.json"],
  ["P42ForcedInclusionController", "artifacts/src/P42ForcedInclusionController.sol/P42ForcedInclusionController.json"],
  ["P42MultisigTimelock", "artifacts/src/P42MultisigTimelock.sol/P42MultisigTimelock.json"],
  ["P42PayoutLedger", "artifacts/src/P42PayoutLedger.sol/P42PayoutLedger.json"],
  ["P42ProblemRegistry", "artifacts/src/P42ProblemRegistry.sol/P42ProblemRegistry.json"],
  ["P42RolloverVault", "artifacts/src/P42RolloverVault.sol/P42RolloverVault.json"],
  ["P42SP1VerifierGateway", "artifacts/src/P42SP1VerifierGateway.sol/P42SP1VerifierGateway.json"],
  ["P42ResolverQuorum", "artifacts/src/P42ResolverQuorum.sol/P42ResolverQuorum.json"],
  ["P42SubmissionManager", "artifacts/src/P42SubmissionManager.sol/P42SubmissionManager.json"],
  ["P42SubmissionManagerFactory", "artifacts/src/P42SubmissionManagerFactory.sol/P42SubmissionManagerFactory.json"],
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
