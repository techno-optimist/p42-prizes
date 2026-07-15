import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const agentRoot = resolve(here, "..");
const repositorySchemas = resolve(agentRoot, "../schemas");
const packageSchemas = resolve(agentRoot, "schemas");
const names = [
  "challenge-provisioning.schema.json",
  "deployment-manifest.schema.json",
  "deployment-manifest-v2.schema.json",
  "funding-activation-signatures-v2.schema.json",
  "indexer-checkpoint-v2.schema.json",
  "indexer-checkpoint-v3.schema.json",
  "indexer-checkpoint-v4.schema.json",
  "runner-health-v2.schema.json",
];

mkdirSync(packageSchemas, { recursive: true });
for (const name of names) {
  const source = resolve(repositorySchemas, name);
  const target = resolve(packageSchemas, name);
  copyFileSync(source, target);
  if (!readFileSync(source).equals(readFileSync(target))) throw new Error(`packaged schema drift: ${name}`);
}
