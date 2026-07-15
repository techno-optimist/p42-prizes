import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { AbiCoder, keccak256, toUtf8Bytes } from "ethers";

const coder = AbiCoder.defaultAbiCoder();
const repeat = (byte, count = 32) => `0x${byte.repeat(count)}`;
const address = (byte) => repeat(byte, 20);

describe("P42 objective journal conformance", () => {
  it("matches the Rust/SP1 Hadamard witness across the complete Solidity hash chain", () => {
    const solution = readFileSync(
      new URL("../../problems/hadamard-668-defect/examples/sylvester-prefix.json", import.meta.url),
    );
    const identity = JSON.parse(
      readFileSync(
        new URL(
          "../../objective-programs/artifacts/hadamard-668-defect/v0.1.0/identity.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    const solutionSha256 = `0x${createHash("sha256").update(solution).digest("hex")}`;
    assert.equal(solutionSha256, "0x4021e45669d91b63179c730309eb26613e4584aa63ee7ec928b32cd4b1ed2bc6");

    const chainId = 84_532n;
    const quorum = address("11");
    const manager = address("22");
    const submissionManager = address("33");
    const registry = address("44");
    const problemId = 10n;
    const packageHash = repeat("55");
    const submissionId = 7n;
    const solver = address("66");
    const commitment = repeat("77");
    const solutionCid = "ipfs://p42-objective-fixture";
    const claimedScoreAtoms = 55_444n * 10n ** 18n;
    const challengeEndsAt = 2_000_000_300n;
    const challenger = address("88");
    const reasonHash = repeat("99");
    const challengedAt = 2_000_000_100n;
    const disputeEndsAt = 2_000_000_200n;
    const transcriptHash = repeat("aa");
    const transcriptUri = "ipfs://p42-transcript-fixture";
    const verdictHash = repeat("bb");
    const proofBeneficiary = address("cc");
    const guestElfSha256 = identity.guestElfSha256.replace("sha256:", "0x");

    const revealInstanceHash = keccak256(
      coder.encode(
        ["address", "uint256", "uint256", "address", "bytes32", "bytes32", "bytes32", "int256", "uint256", "uint64"],
        [submissionManager, chainId, submissionId, solver, commitment, solutionSha256, keccak256(toUtf8Bytes(solutionCid)), claimedScoreAtoms, 0n, challengeEndsAt],
      ),
    );
    assert.equal(revealInstanceHash, "0x6ee19d1c3507c2c449a683562d4281b0e9e3ad14e43c4824b19ed8f8a214464f");

    const challengeInstanceHash = keccak256(
      coder.encode(
        ["address", "uint256", "uint256", "bytes32", "address", "bytes32", "uint64", "uint64"],
        [manager, chainId, submissionId, revealInstanceHash, challenger, reasonHash, challengedAt, disputeEndsAt],
      ),
    );
    assert.equal(challengeInstanceHash, "0xfc622c915a05ed6abec27aa5962a517a0d3a3d6775c06b7a854a204165ed515c");

    const pendingDecisionContext = keccak256(
      coder.encode(
        ["bytes32", "bytes32", "address", "bytes32", "bool", "bytes32", "bytes32", "bytes32"],
        [challengeInstanceHash, revealInstanceHash, challenger, reasonHash, false, transcriptHash, keccak256(toUtf8Bytes(transcriptUri)), verdictHash],
      ),
    );
    assert.equal(pendingDecisionContext, "0x92497c367627e52a877e4b4058dc62fec7a0f5a2098ed790e86ad4f3e4b4978f");

    const objectiveBindingContext = keccak256(
      coder.encode(
        ["address", "uint256", "bytes32", "bytes32", "bytes32"],
        [registry, problemId, packageHash, guestElfSha256, identity.programVKey],
      ),
    );
    assert.equal(objectiveBindingContext, "0xc2dcbb9f03ffe5af658908c9778d0f03284f096ad2c2786c5e9c5c27efc49ead");

    const contextHash = keccak256(
      coder.encode(
        ["string", "uint256", "address", "address", "bytes32", "uint256", "bytes32"],
        ["P42_OBJECTIVE_CHALLENGE_CONTEXT_V2", chainId, manager, submissionManager, objectiveBindingContext, submissionId, pendingDecisionContext],
      ),
    );
    assert.equal(contextHash, "0xe639b8c967f4abf2f8dfdeb588c4e8b25e6026aec4095b2ae54f616d72790592");

    const journalDigest = keccak256(
      coder.encode(
        ["string", "uint256", "address", "address", "bytes32", "bytes32", "bytes32", "bool", "address"],
        ["P42_OBJECTIVE_VERDICT_JOURNAL_V2", chainId, quorum, manager, guestElfSha256, identity.programVKey, contextHash, true, proofBeneficiary],
      ),
    );
    assert.equal(journalDigest, "0xf9be0e1ef3a8990ff478ee36b5890d3d9cf30b269269094f3f28b1b02f715546");
  });

  it("matches the Rust/SP1 A11 witness across the complete Solidity hash chain", () => {
    const solution = readFileSync(
      new URL(
        "../../problems/distinct-subset-sums-a11/tests/conway-guy-594.json",
        import.meta.url,
      ),
    );
    const artifactRoot = "../../objective-programs/artifacts/distinct-subset-sums-a11/v0.1.0";
    const identity = JSON.parse(
      readFileSync(new URL(`${artifactRoot}/identity.json`, import.meta.url), "utf8"),
    );
    const vector = JSON.parse(
      readFileSync(new URL(`${artifactRoot}/journal-vector.json`, import.meta.url), "utf8"),
    );
    const execution = JSON.parse(
      readFileSync(new URL(`${artifactRoot}/execution.json`, import.meta.url), "utf8"),
    );
    const witness = vector.witness;
    const solutionSha256 = `0x${createHash("sha256").update(solution).digest("hex")}`;
    assert.equal(solutionSha256, witness.solutionSha256);
    assert.equal(witness.guestElfSha256, identity.guestElfSha256.replace("sha256:", "0x"));
    assert.equal(witness.programVKey, identity.programVKey);

    const chainId = BigInt(witness.chainId);
    const quorum = witness.quorum;
    const manager = witness.manager;
    const submissionManager = witness.submissionManager;
    const registry = witness.registry;
    const problemId = BigInt(witness.problemId);
    const packageHash = witness.objectivePackageHash;
    const guestElfSha256 = witness.guestElfSha256;
    const programVKey = witness.programVKey;
    const submissionId = BigInt(witness.submissionId);
    const solver = witness.solver;
    const commitment = witness.commitment;
    const solutionCid = witness.solutionCid;
    const claimedScoreAtoms = BigInt(witness.claimedScoreAtoms);
    const challengeEndsAt = BigInt(witness.challengeEndsAt);
    const challenger = witness.challenger;
    const reasonHash = witness.reasonHash;
    const challengedAt = BigInt(witness.challengedAt);
    const disputeEndsAt = BigInt(witness.disputeEndsAt);
    const transcriptHash = witness.transcriptHash;
    const transcriptUri = witness.transcriptUri;
    const verdictHash = witness.verdictHash;
    const proofBeneficiary = witness.proofBeneficiary;

    const revealInstanceHash = keccak256(
      coder.encode(
        ["address", "uint256", "uint256", "address", "bytes32", "bytes32", "bytes32", "int256", "uint256", "uint64"],
        [submissionManager, chainId, submissionId, solver, commitment, solutionSha256, keccak256(toUtf8Bytes(solutionCid)), claimedScoreAtoms, BigInt(witness.improvementAtoms), challengeEndsAt],
      ),
    );
    assert.equal(keccak256(toUtf8Bytes(solutionCid)), vector.hashes.solutionCidHash);
    assert.equal(revealInstanceHash, vector.hashes.revealInstanceHash);

    const challengeInstanceHash = keccak256(
      coder.encode(
        ["address", "uint256", "uint256", "bytes32", "address", "bytes32", "uint64", "uint64"],
        [manager, chainId, submissionId, revealInstanceHash, challenger, reasonHash, challengedAt, disputeEndsAt],
      ),
    );
    assert.equal(challengeInstanceHash, vector.hashes.challengeInstanceHash);

    const pendingDecisionContext = keccak256(
      coder.encode(
        ["bytes32", "bytes32", "address", "bytes32", "bool", "bytes32", "bytes32", "bytes32"],
        [challengeInstanceHash, revealInstanceHash, challenger, reasonHash, witness.pendingChallengerWins, transcriptHash, keccak256(toUtf8Bytes(transcriptUri)), verdictHash],
      ),
    );
    assert.equal(keccak256(toUtf8Bytes(transcriptUri)), vector.hashes.transcriptUriHash);
    assert.equal(pendingDecisionContext, vector.hashes.pendingDecisionContext);

    const objectiveBindingContext = keccak256(
      coder.encode(
        ["address", "uint256", "bytes32", "bytes32", "bytes32"],
        [registry, problemId, packageHash, guestElfSha256, programVKey],
      ),
    );
    assert.equal(objectiveBindingContext, vector.hashes.objectiveBindingContext);

    const contextHash = keccak256(
      coder.encode(
        ["string", "uint256", "address", "address", "bytes32", "uint256", "bytes32"],
        ["P42_OBJECTIVE_CHALLENGE_CONTEXT_V2", chainId, manager, submissionManager, objectiveBindingContext, submissionId, pendingDecisionContext],
      ),
    );
    assert.equal(contextHash, vector.hashes.contextHash);

    const journalDigest = keccak256(
      coder.encode(
        ["string", "uint256", "address", "address", "bytes32", "bytes32", "bytes32", "bool", "address"],
        ["P42_OBJECTIVE_VERDICT_JOURNAL_V2", chainId, quorum, manager, guestElfSha256, programVKey, contextHash, witness.correctedChallengerWins, proofBeneficiary],
      ),
    );
    assert.equal(journalDigest, vector.hashes.journalDigest);
    assert.equal(journalDigest, execution.journalDigest);
  });
});
