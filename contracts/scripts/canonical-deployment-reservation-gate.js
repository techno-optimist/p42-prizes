import {
  CANONICAL_CONTRACT_COUNT,
  assertCanonicalDeploymentPlan,
} from "p42-agent/canonical-topology.mjs";

function deploymentMembers(definitions) {
  return definitions.map(({ id, name }) => `${id}:${name}`).sort();
}

export function assertCanonicalDefinitionTopology({
  canonicalDefinitions,
  executableDefinitions,
  boardCount,
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
}

export async function resolveCanonicalDeploymentStartNonce({
  canonicalDefinitions,
  executableDefinitions,
  boardCount,
  existingStartNonce,
  readPendingNonce,
}) {
  assertCanonicalDefinitionTopology({ canonicalDefinitions, executableDefinitions, boardCount });
  return existingStartNonce ?? readPendingNonce();
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

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

export async function validateAndReserveCanonicalDeployment({
  canonicalDefinitions,
  executableDefinitions,
  boardCount,
  executablePreflight,
  setupOperations,
  expectedOperationCount,
  validateDeploymentPlan,
  validateSetupOperations,
  reserve,
}) {
  assertCanonicalDefinitionTopology({ canonicalDefinitions, executableDefinitions, boardCount });
  if (
    executablePreflight.definitions !== executableDefinitions
    || executablePreflight.steps.length !== CANONICAL_CONTRACT_COUNT
    || executablePreflight.steps.some((step, index) => (
      step.id !== executableDefinitions[index].id || step.name !== executableDefinitions[index].name
    ))
  ) throw new Error(`multi-board executable preflight must contain exactly ${CANONICAL_CONTRACT_COUNT} canonical steps`);
  if (setupOperations.length !== expectedOperationCount) {
    throw new Error("pre-broadcast v2 operation plan is incomplete");
  }
  if (typeof validateDeploymentPlan !== "function" || typeof validateSetupOperations !== "function") {
    throw new Error("canonical deployment reservation requires exact payload and operation validators");
  }

  const validatedDeploymentPlan = await validateDeploymentPlan(executablePreflight);
  if (
    validatedDeploymentPlan?.transactionCount !== CANONICAL_CONTRACT_COUNT
    || !/^sha256:[0-9a-f]{64}$/.test(validatedDeploymentPlan.planDigest ?? "")
  ) throw new Error("canonical deployment payload validator returned an incomplete binding");
  const validatedSetupPlan = await validateSetupOperations(setupOperations);
  if (
    validatedSetupPlan?.operationCount !== expectedOperationCount
    || !/^sha256:[0-9a-f]{64}$/.test(validatedSetupPlan.operationsDigest ?? "")
  ) throw new Error("canonical setup operation validator returned an incomplete binding");
  const frozenPreflight = freezeExecutablePreflight(executablePreflight);
  const frozenSetupOperations = deepFreeze(setupOperations);
  deepFreeze(validatedDeploymentPlan);
  deepFreeze(validatedSetupPlan);
  const reservation = await reserve();
  return {
    frozenPreflight,
    frozenSetupOperations,
    validatedDeploymentPlan,
    validatedSetupPlan,
    reservation,
  };
}
