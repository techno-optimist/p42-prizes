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

The test deploys the seven canonical shared contracts and four contracts per
board (47 contracts total). It derives all 110 governance setup
operations through the production helper and reserves their complete ordered
identity in a private, no-follow journal before the first schedule. Journal
generations use file fsync, atomic same-directory rename, and parent-directory
fsync. The rehearsal executes operation 37 and injects a crash before that
receipt is journaled. Restart queries `stateOf`, validates the unique local
`Scheduled` and `Executed` events plus the internally consistent successful
receipt/block binding at one explicit local block,
recovers the missing observation, and runs every remaining operation exactly
once. Reconciliation then
checks all ten sequential registrations, immutable freezes, ownership and
wiring, zero pool/vault balances, and both funding gates false.

This proves local construction, execution, durable journal replay, recovery of
the mined-before-persisted crash window, and final-state reconciliation. The
journal also fails closed on plan substitution, regression, conflicting receipt
evidence, permissive files, symlinks, and byte tampering. It does not prove
actual host power-loss behavior, admission matrices, release hashes, testnet
gas/finality, signer custody, explorer verification, or authorization to deploy.
