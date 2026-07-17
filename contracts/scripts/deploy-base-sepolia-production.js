import {
  PRODUCTION_DEPLOY_MODE,
  runCanonicalProductionEntryPoint,
} from "./base-sepolia-deployment-entrypoint.js";

globalThis[Symbol.for("p42-prizes.deploy-base-sepolia.library-import")] = true;
const { runBaseSepoliaDeployment } = await import("./deploy-base-sepolia.js");

await runCanonicalProductionEntryPoint({
  requestedMode: process.env.P42_DEPLOY_MODE,
  dispatch: (mode) => {
    if (mode !== PRODUCTION_DEPLOY_MODE) {
      throw new Error("internal error: canonical deployment selected a non-production planner");
    }
    return runBaseSepoliaDeployment({ mode });
  },
});
