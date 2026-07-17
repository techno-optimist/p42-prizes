import {
  CANONICAL_CONTRACT_COUNT,
  assertCanonicalDeploymentPlan,
} from "../../agent/canonical-topology.mjs";

function deploymentMembers(definitions) {
  return definitions.map(({ id, name }) => `${id}:${name}`).sort();
}

function freezeExecutablePreflight(plan) {
  for (const step of plan.steps) {
    if (step.unsigned && typeof step.unsigned === "object") Object.freeze(step.unsigned);
    Object.freeze(step);
  }
  Object.freeze(plan.steps);
  Object.freeze(plan.addresses);
  Object.freeze(plan.definitions);
  return Object.freeze(plan);
}

export async function validateAndReserveCanonicalDeployment({
  canonicalDefinitions,
  executableDefinitions,
  boardCount,
  executablePreflight,
  setupOperations,
  expectedOperationCount,
  reserve,
}) {
  assertCanonicalDeploymentPlan(canonicalDefinitions, boardCount);
  if (executableDefinitions.length !== CANONICAL_CONTRACT_COUNT) {
    throw new Error(
      `multi-board executable preflight requires exactly ${CANONICAL_CONTRACT_COUNT} contract definitions`,
    );
  }
  if (JSON.stringify(deploymentMembers(canonicalDefinitions))
      !== JSON.stringify(deploymentMembers(executableDefinitions))) {
    throw new Error("canonical manifest and executable deployment membership differ");
  }
  if (
    executablePreflight.definitions !== executableDefinitions
    || executablePreflight.steps.length !== CANONICAL_CONTRACT_COUNT
    || executablePreflight.steps.some((step) => !step.expectedInitCode || !step.unsigned?.data)
  ) {
    throw new Error(`multi-board executable preflight did not freeze all ${CANONICAL_CONTRACT_COUNT} initcode/calldata payloads`);
  }
  if (setupOperations.length !== expectedOperationCount) {
    throw new Error("pre-broadcast v2 operation plan is incomplete");
  }

  const frozenPreflight = freezeExecutablePreflight(executablePreflight);
  const reservation = await reserve();
  return { frozenPreflight, reservation };
}
