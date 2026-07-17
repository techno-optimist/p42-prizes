import {
  PRODUCTION_DEPLOY_MODE,
  requireCanonicalProductionMode,
  runCanonicalProductionEntryPoint,
} from "./base-sepolia-deployment-entrypoint.js";

const mode = requireCanonicalProductionMode(process.env.P42_DEPLOY_MODE);
globalThis[Symbol.for("p42-prizes.deploy-base-sepolia.library-import")] = true;
const { runBaseSepoliaDeployment } = await import("./deploy-base-sepolia.js");

await runCanonicalProductionEntryPoint({
  requestedMode: mode,
  dispatch: (selectedMode) => {
    if (selectedMode !== PRODUCTION_DEPLOY_MODE) {
      throw new Error("internal error: canonical deployment selected a non-production planner");
    }
    return runBaseSepoliaDeployment({ mode: selectedMode });
  },
});
