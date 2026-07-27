import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { ethers } from "ethers";

import { canonicalTopologyDescriptors } from "p42-agent/canonical-topology.mjs";
import { assertExactSetupOperations } from "p42-agent/setup-operation-plan.mjs";
import {
  resolveCanonicalDeploymentStartNonce,
  validateAndReserveCanonicalDeployment,
} from "../scripts/canonical-deployment-reservation-gate.js";
import { bindGovernanceOperationPlan } from "../scripts/governance-operation-journal.js";
import {
  buildExecutableDeploymentNoncePlan,
  buildTrustedRpcEvidence,
} from "../scripts/signed-deployment-journal.js";

const DEPLOYER = "0x0000000000000000000000000000000000000042";
const RPC_EVIDENCE = buildTrustedRpcEvidence({
  primaryUrl: "https://primary.example/rpc",
  secondaryUrl: "https://secondary.example/rpc",
  primaryOperatorId: "operator-a",
  secondaryOperatorId: "operator-b",
});

function preflight(definitions) {
  const startNonce = 12;
  const steps = definitions.map((definition, index) => {
    const expectedInitCode = `0x60${index.toString(16).padStart(2, "0")}`;
    return {
      ...definition,
      addressKey: definition.id,
      kind: "direct-create",
      expectedInitCode,
      constructorArgsHash: ethers.id(`constructor-${index}`),
      unsigned: { data: expectedInitCode },
    };
  });
  return {
    definitions,
    startNonce,
    addresses: Object.fromEntries(steps.map(({ addressKey }, index) => [
      addressKey,
      ethers.getCreateAddress({ from: DEPLOYER, nonce: startNonce + index }),
    ])),
    steps,
  };
}

function setupOperations(count = 110) {
  return Array.from({ length: count }, (_, index) => {
    const target = `0x${(index + 1).toString(16).padStart(40, "0")}`;
    const data = `0x${index.toString(16).padStart(2, "0")}`;
    const salt = ethers.id(`operation-${index}`);
    const operationId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "uint256", "bytes", "bytes32"],
      [target, 0, data, salt],
    ));
    return {
      sequence: index + 1,
      label: `operation-${index + 1}`,
      operationClass: "standard",
      target,
      value: "0",
      data,
      salt,
      operationId,
      dependsOn: [],
      requiredConfirmations: "2",
      delaySeconds: "60",
      transactionBuilder: { method: "schedule", args: [target, "0", data, salt] },
      overrideFallback: null,
    };
  });
}

function deploymentValidator(plan) {
  return buildExecutableDeploymentNoncePlan(ethers, {
    identityDigest: `sha256:${"1".repeat(64)}`,
    network: "baseSepolia",
    chainId: 84532,
    deployer: DEPLOYER,
    rpcEvidence: RPC_EVIDENCE,
    startNonce: plan.startNonce,
  }, plan.steps, plan.addresses);
}

describe("canonical deployment reservation gate", () => {
  it("validates definition topology before pending nonce lookup", async () => {
    const definitions = canonicalTopologyDescriptors().map(({ id, name }) => ({ id, name }));
    let nonceReads = 0;
    const readPendingNonce = async () => {
      nonceReads += 1;
      return 12;
    };

    for (const testCase of [
      {
        canonicalDefinitions: definitions.slice(0, -1),
        executableDefinitions: definitions,
        expectedError: /canonical 47-contract topology/,
      },
      {
        canonicalDefinitions: definitions,
        executableDefinitions: definitions.slice(0, -1),
        expectedError: /exactly 47 contract definitions/,
      },
      {
        canonicalDefinitions: definitions,
        executableDefinitions: definitions.map((definition, index) => (
          index === 46 ? { ...definition, name: "WrongContract" } : definition
        )),
        expectedError: /deployment membership differ/,
      },
    ]) {
      await assert.rejects(resolveCanonicalDeploymentStartNonce({
        ...testCase,
        boardCount: 10,
        readPendingNonce,
      }), testCase.expectedError);
    }
    assert.equal(nonceReads, 0);

    assert.equal(await resolveCanonicalDeploymentStartNonce({
      canonicalDefinitions: definitions,
      executableDefinitions: definitions,
      boardCount: 10,
      readPendingNonce,
    }), 12);
    assert.equal(nonceReads, 1);
    assert.equal(await resolveCanonicalDeploymentStartNonce({
      canonicalDefinitions: definitions,
      executableDefinitions: definitions,
      boardCount: 10,
      existingStartNonce: 9,
      readPendingNonce,
    }), 9);
    assert.equal(nonceReads, 1);
  });

  it("validates every payload and setup operation before one reservation", async () => {
    const root = await mkdtemp(join(tmpdir(), "p42-canonical-reservation-"));
    try {
      const reservationPath = join(root, "p42-prizes.json.deployment-reservation.json");
      const definitions = canonicalTopologyDescriptors().map(({ id, name }) => ({ id, name }));
      let reservationCalls = 0;
      let deploymentValidationCalls = 0;
      let setupValidationCalls = 0;
      const canonicalSetupOperations = setupOperations();
      const reserve = async () => {
        reservationCalls += 1;
        await writeFile(reservationPath, "reserved\n", { flag: "wx" });
        return { path: reservationPath };
      };
      const validateDeploymentPlan = (plan) => {
        deploymentValidationCalls += 1;
        return deploymentValidator(plan);
      };
      const validateSetupOperations = (operations) => {
        setupValidationCalls += 1;
        assertExactSetupOperations(canonicalSetupOperations, operations);
        return bindGovernanceOperationPlan(operations);
      };
      const common = {
        boardCount: 10,
        executableDefinitions: definitions,
        executablePreflight: preflight(definitions),
        setupOperations: structuredClone(canonicalSetupOperations),
        expectedOperationCount: 110,
        validateDeploymentPlan,
        validateSetupOperations,
        reserve,
      };

      const duplicateNonHex = preflight(definitions);
      duplicateNonHex.steps = duplicateNonHex.steps.map((step) => ({
        ...step,
        expectedInitCode: "truthy-not-hex",
        unsigned: { data: "truthy-not-hex" },
      }));
      await assert.rejects(validateAndReserveCanonicalDeployment({
        ...common,
        canonicalDefinitions: definitions,
        executablePreflight: duplicateNonHex,
      }), /invalid BytesLike value/);
      assert.equal(deploymentValidationCalls, 1);
      assert.equal(setupValidationCalls, 0);

      await assert.rejects(validateAndReserveCanonicalDeployment({
        ...common,
        canonicalDefinitions: definitions,
        setupOperations: Array.from({ length: 110 }, () => ({})),
      }));
      assert.equal(deploymentValidationCalls, 2);
      assert.equal(setupValidationCalls, 1);

      const mismatchedBytes = preflight(definitions);
      mismatchedBytes.steps[46] = {
        ...mismatchedBytes.steps[46],
        unsigned: { data: "0x6000" },
      };
      await assert.rejects(validateAndReserveCanonicalDeployment({
        ...common,
        canonicalDefinitions: definitions,
        executablePreflight: mismatchedBytes,
      }), /bytes differ from expected initcode/);

      const relabeledStep = preflight(definitions);
      relabeledStep.steps[46] = { ...relabeledStep.steps[46], id: definitions[0].id };
      await assert.rejects(validateAndReserveCanonicalDeployment({
        ...common,
        canonicalDefinitions: definitions,
        executablePreflight: relabeledStep,
      }), /exactly 47 canonical steps/);

      await assert.rejects(validateAndReserveCanonicalDeployment({
        ...common,
        canonicalDefinitions: definitions,
        validateDeploymentPlan: () => undefined,
      }), /validator returned an incomplete binding/);

      const alteredOperations = setupOperations();
      alteredOperations[109] = { ...alteredOperations[109], data: "0xffff" };
      assert.throws(() => bindGovernanceOperationPlan(alteredOperations), /operation id does not match payload/);

      const internallyValidNoncanonical = setupOperations();
      internallyValidNoncanonical[109] = {
        ...internallyValidNoncanonical[109],
        data: "0xffff",
      };
      internallyValidNoncanonical[109].operationId = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "uint256", "bytes", "bytes32"],
          [
            internallyValidNoncanonical[109].target,
            0,
            internallyValidNoncanonical[109].data,
            internallyValidNoncanonical[109].salt,
          ],
        ),
      );
      assert.doesNotThrow(() => bindGovernanceOperationPlan(internallyValidNoncanonical));
      await assert.rejects(validateAndReserveCanonicalDeployment({
        ...common,
        canonicalDefinitions: definitions,
        setupOperations: internallyValidNoncanonical,
      }), /does not match the exact derived governance operation/);

      assert.equal(reservationCalls, 0);
      assert.equal(existsSync(reservationPath), false);

      deploymentValidationCalls = 0;
      setupValidationCalls = 0;
      const {
        frozenPreflight,
        frozenSetupOperations,
        validatedDeploymentPlan,
        validatedSetupPlan,
        reservation,
      } = await validateAndReserveCanonicalDeployment({
        ...common,
        canonicalDefinitions: definitions,
      });
      assert.equal(deploymentValidationCalls, 1);
      assert.equal(setupValidationCalls, 1);
      assert.equal(reservationCalls, 1);
      assert.equal(reservation.path, reservationPath);
      assert.equal(Object.isFrozen(frozenPreflight), true);
      assert.equal(Object.isFrozen(frozenPreflight.steps), true);
      assert.equal(frozenPreflight.steps.length, 47);
      assert.equal(Object.isFrozen(frozenSetupOperations), true);
      assert.equal(Object.isFrozen(frozenSetupOperations[109].transactionBuilder), true);
      assert.equal(frozenSetupOperations.length, 110);
      assert.equal(validatedDeploymentPlan.transactionCount, 47);
      assert.equal(validatedSetupPlan.operationCount, 110);
      assert.equal(Object.isFrozen(validatedDeploymentPlan), true);
      assert.equal(Object.isFrozen(validatedSetupPlan), true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
