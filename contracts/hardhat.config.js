import hardhatEthersPlugin from "@nomicfoundation/hardhat-ethers";
import hardhatNodeTestRunnerPlugin from "@nomicfoundation/hardhat-node-test-runner";
import { defineConfig } from "hardhat/config";

export default defineConfig({
  plugins: [hardhatEthersPlugin, hardhatNodeTestRunnerPlugin],
  solidity: {
    profiles: {
      default: {
        version: "0.8.24",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        }
      }
    }
  },
  paths: {
    sources: "./src",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  }
});
