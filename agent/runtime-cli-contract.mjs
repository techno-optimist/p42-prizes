const CONTRACTS = Object.freeze({
  operator: Object.freeze({
    executable: "/opt/p42/agent/operator.mjs",
    requiredValueOptions: Object.freeze([
      "--rpc",
      "--nonce-rpc-secondary",
      "--manifest",
      "--problem",
      "--registry-problem-id",
      "--repo-root",
      "--runtime",
      "--coordination-root",
      "--challenge-provisioning",
      "--agent-wallet",
      "--runner-health-public-key",
      "--runner-recovery-public-key",
      "--runner-host-id",
      "--runner-boot-id",
      "--runner-queue-id",
    ]),
  }),
  resolver: Object.freeze({
    executable: "/opt/p42/agent/resolver.mjs",
    requiredValueOptions: Object.freeze([
      "--rpc",
      "--manifest",
      "--problem-id",
      "--registry-problem-id",
      "--transcripts",
      "--quorum-signatures",
      "--runtime",
      "--coordination-root",
      "--agent-wallet",
    ]),
    publisherOptions: Object.freeze(["--transcript-store", "--publication-receipts"]),
    retrievalEndpointOption: "--transcript-endpoint",
    minimumRetrievalEndpoints: 2,
  }),
});

export const PRODUCTION_RUNTIME_CLI_CONTRACTS = CONTRACTS;

export function optionValues(argv, option) {
  const values = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] !== option) continue;
    const value = argv[index + 1];
    if (value && !value.startsWith("--")) values.push(value);
  }
  return values;
}

function optionOccurrences(argv, option) {
  return argv.filter((value) => value === option).length;
}

export function productionRuntimeContractErrors(role, argv, {
  env = process.env,
  publisherProvided = false,
  endpointsProvided = [],
} = {}) {
  const contract = CONTRACTS[role];
  if (!contract) throw new Error(`unknown production runtime role: ${role}`);
  const errors = [];
  for (const option of contract.requiredValueOptions) {
    if (optionOccurrences(argv, option) !== 1 || optionValues(argv, option).length !== 1) {
      errors.push(`${option} must be provided exactly once with a value`);
    }
  }
  if (argv.includes("--local-test")) errors.push("--local-test is forbidden in production runtime units");

  if (role === "resolver") {
    const publisherOccurrences = contract.publisherOptions
      .reduce((count, option) => count + optionOccurrences(argv, option), 0);
    const publisherValues = contract.publisherOptions
      .reduce((count, option) => count + optionValues(argv, option).length, 0);
    const expectedPublisherOptions = publisherProvided ? 0 : 1;
    if (publisherOccurrences !== expectedPublisherOptions || publisherValues !== expectedPublisherOptions) {
      errors.push("configure exactly one of --transcript-store or --publication-receipts");
    }
    if (optionValues(argv, "--transcript-store").some((value) => value !== "arweave")) {
      errors.push("--transcript-store must be arweave");
    }
    const environmentEndpoints = String(env.P42_TRANSCRIPT_ENDPOINTS ?? "")
      .split(",").map((value) => value.trim()).filter(Boolean);
    const endpoints = [
      ...optionValues(argv, contract.retrievalEndpointOption),
      ...environmentEndpoints,
      ...endpointsProvided,
    ];
    if (endpoints.length < contract.minimumRetrievalEndpoints) {
      errors.push(`at least ${contract.minimumRetrievalEndpoints} transcript retrieval endpoints are required`);
    }
    if (optionOccurrences(argv, contract.retrievalEndpointOption)
        !== optionValues(argv, contract.retrievalEndpointOption).length) {
      errors.push("each --transcript-endpoint must have a value");
    }
  }
  return errors;
}

export function assertProductionRuntimeContract(role, argv, options = {}) {
  const errors = productionRuntimeContractErrors(role, argv, options);
  if (errors.length) throw new Error(`production ${role} CLI contract: ${errors.join("; ")}`);
}
