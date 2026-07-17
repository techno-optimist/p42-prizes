export const PRODUCTION_DEPLOY_MODE = "deploy-multiboard-production";
export const TEST_ONLY_LEGACY_DEPLOY_MODE = "test-only-legacy-single-board";
export const CONTINUE_DEPLOY_MODE = "continue";
export const INSPECT_RESERVATION_MODE = "inspect-reservation";

const EXPLICIT_MODES = new Set([
  PRODUCTION_DEPLOY_MODE,
  TEST_ONLY_LEGACY_DEPLOY_MODE,
  CONTINUE_DEPLOY_MODE,
  INSPECT_RESERVATION_MODE,
]);

export function requireExplicitDeployMode(value) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error("P42_DEPLOY_MODE is required; no deployment topology is selected by default");
  }
  const mode = value.trim().toLowerCase();
  if (!EXPLICIT_MODES.has(mode)) {
    throw new Error(
      `P42_DEPLOY_MODE must be ${[...EXPLICIT_MODES].join(", ")}`,
    );
  }
  return mode;
}

export async function dispatchBaseSepoliaDeployment({
  requestedMode,
  requireRpc,
  inspectReservation,
  connectRpc,
  deployProduction,
  deployLegacyTestOnly,
  continueDeployment,
}) {
  const mode = requireExplicitDeployMode(requestedMode);
  if (mode === INSPECT_RESERVATION_MODE) return inspectReservation();

  requireRpc();
  const connection = await connectRpc();
  try {
    if (mode === PRODUCTION_DEPLOY_MODE) return await deployProduction(connection);
    if (mode === TEST_ONLY_LEGACY_DEPLOY_MODE) return await deployLegacyTestOnly(connection);
    return await continueDeployment(connection);
  } finally {
    await connection.close();
  }
}

export async function runCanonicalProductionEntryPoint({ requestedMode, dispatch }) {
  const mode = requireExplicitDeployMode(requestedMode);
  if (mode !== PRODUCTION_DEPLOY_MODE) {
    throw new Error(
      `canonical Base Sepolia deployment requires P42_DEPLOY_MODE=${PRODUCTION_DEPLOY_MODE}`,
    );
  }
  return dispatch(PRODUCTION_DEPLOY_MODE);
}
