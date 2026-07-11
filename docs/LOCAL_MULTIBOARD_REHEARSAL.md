# Local Multi-Board Ceremony Rehearsal

This rehearsal is a no-broadcast proof of the production ceremony's topology.
It uses Hardhat chain ID `31337`, funded ephemeral accounts, and no RPC URL,
private key, Base Sepolia credential, pool deposit, `armFunding`, or
`setAcceptingFunds(true)` call.

Run from `contracts/`:

```sh
npx hardhat test test/local-multiboard-rehearsal.test.js
```

The checked-in fixture names the current ten launch-board packages and has the
same strict `p42-prizes/multi-board-ceremony/v1` shape as the Base Sepolia
input. Its hashes and URIs are explicitly local test anchors, not release
evidence and not deployable production values.

The test deploys one timelock, one registry, one rollover vault, and four child
contracts per board (43 contracts total). It derives all 110 governance setup
operations through the production helper, executes 37, injects an in-process
interruption, reloads the local test journal, verifies every recorded operation is
already executed, and runs the remaining 73 exactly once. Reconciliation then
checks all ten sequential registrations, immutable freezes, ownership and
wiring, zero pool/vault balances, and both funding gates false.

This proves local construction, execution, logical replay idempotence, and
final-state reconciliation. The test journal is ordinary local test storage; it
does not prove crash-durable deployment journaling or filesystem power-loss
safety. It also does not prove admission matrices, release hashes, testnet
gas/finality, signer custody, explorer verification, or authorization to deploy.
