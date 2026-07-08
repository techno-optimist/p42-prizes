import hardhatEthersPlugin from "@nomicfoundation/hardhat-ethers";
import hardhatNodeTestRunnerPlugin from "@nomicfoundation/hardhat-node-test-runner";
import { defineConfig } from "hardhat/config";

const baseSepoliaAccounts = process.env.BASE_SEPOLIA_PRIVATE_KEY
  ? [process.env.BASE_SEPOLIA_PRIVATE_KEY]
  : "remote";

export default defineConfig({
  plugins: [hardhatEthersPlugin, hardhatNodeTestRunnerPlugin],
  chainDescriptors: {
    84532: {
      name: "Base Sepolia",
      chainType: "op",
      blockExplorers: {
        etherscan: {
          name: "BaseScan Sepolia",
          url: "https://sepolia.basescan.org",
          apiUrl: "https://api-sepolia.basescan.org/api"
        }
      }
    }
  },
  networks: {
    baseSepolia: {
      type: "http",
      chainType: "op",
      chainId: 84532,
      url: process.env.BASE_SEPOLIA_RPC_URL ?? "http://127.0.0.1:8545",
      accounts: baseSepoliaAccounts
    }
  },
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
