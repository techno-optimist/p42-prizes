export async function deployActiveObjectiveProofCapability(ethers) {
  const Gateway = await ethers.getContractFactory("MockObjectiveVerifierGateway");
  const gateway = await Gateway.deploy();
  await gateway.waitForDeployment();
  const objectiveVerifier = await gateway.getAddress();
  const objectiveVerifierCodehash = ethers.keccak256(await ethers.provider.getCode(objectiveVerifier));
  return { gateway, objectiveVerifier, objectiveVerifierCodehash };
}
