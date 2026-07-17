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

  it("matches the isolated Rust/SP1 Q6 witness across the complete Solidity hash chain", () => {
    const solution = readFileSync(
      new URL(
        "../../problems/q6-intersecting-hypergraph/tests/seed-pg25.json",
        import.meta.url,
      ),
    );
    const solutionSha256 = `0x${createHash("sha256").update(solution).digest("hex")}`;
    assert.equal(solutionSha256, "0x4c0e38ba9e174fe95c78de0acc2fa216ade92a52ba41b88ee010fbf7a61092ce");

    const chainId = 84_532n;
    const quorum = address("11");
    const manager = address("22");
    const submissionManager = address("33");
    const registry = address("44");
    const problemId = 1n;
    const packageHash = repeat("55");
    const guestElfSha256 = repeat("dd");
    const programVKey = repeat("ee");
    const submissionId = 7n;
    const solver = address("66");
    const commitment = repeat("77");
    const solutionCid = "ipfs://p42-q6-objective-fixture";
    const claimedScoreAtoms = 17n * 10n ** 18n;
    const improvementAtoms = 1n * 10n ** 18n;
    const challengeEndsAt = 2_000_000_300n;
    const challenger = address("88");
    const reasonHash = repeat("99");
    const challengedAt = 2_000_000_100n;
    const disputeEndsAt = 2_000_000_200n;
    const transcriptHash = repeat("aa");
    const transcriptUri = "ipfs://p42-q6-transcript";
    const verdictHash = repeat("bb");
    const proofBeneficiary = address("cc");

    const solutionCidHash = keccak256(toUtf8Bytes(solutionCid));
    assert.equal(solutionCidHash, "0xd2ffb06d3eb78191f704d4ac8e2384de116ea22b7ed03c6ca3919ab94d00f845");
    const revealInstanceHash = keccak256(
      coder.encode(
        ["address", "uint256", "uint256", "address", "bytes32", "bytes32", "bytes32", "int256", "uint256", "uint64"],
        [submissionManager, chainId, submissionId, solver, commitment, solutionSha256, solutionCidHash, claimedScoreAtoms, improvementAtoms, challengeEndsAt],
      ),
    );
    assert.equal(revealInstanceHash, "0xda17baaaea02ced5e95aa6da5d6fb810db3eeb25e68025b7a7e06c31079d5bdf");

    const challengeInstanceHash = keccak256(
      coder.encode(
        ["address", "uint256", "uint256", "bytes32", "address", "bytes32", "uint64", "uint64"],
        [manager, chainId, submissionId, revealInstanceHash, challenger, reasonHash, challengedAt, disputeEndsAt],
      ),
    );
    assert.equal(challengeInstanceHash, "0x34088a069657760d313b6d425225fd181f4a33a8c51a68f394fc0cf35057a026");

    const transcriptUriHash = keccak256(toUtf8Bytes(transcriptUri));
    assert.equal(transcriptUriHash, "0x211d3fd9383dbe29404bb5e29b1db62b65b5e95265a74c20a079a64e5d2af0e8");
    const pendingDecisionContext = keccak256(
      coder.encode(
        ["bytes32", "bytes32", "address", "bytes32", "bool", "bytes32", "bytes32", "bytes32"],
        [challengeInstanceHash, revealInstanceHash, challenger, reasonHash, false, transcriptHash, transcriptUriHash, verdictHash],
      ),
    );
    assert.equal(pendingDecisionContext, "0x4bb1e84a4dea50460227e02d8c898f5ab2edfcadb7576b7761cc64c573f51005");

    const objectiveBindingContext = keccak256(
      coder.encode(
        ["address", "uint256", "bytes32", "bytes32", "bytes32"],
        [registry, problemId, packageHash, guestElfSha256, programVKey],
      ),
    );
    assert.equal(objectiveBindingContext, "0xa924ed91d5d18434133dc08a0f34ceb1bd9a5d5dbc3587bb3ff203d8e59603da");

    const contextHash = keccak256(
      coder.encode(
        ["string", "uint256", "address", "address", "bytes32", "uint256", "bytes32"],
        ["P42_OBJECTIVE_CHALLENGE_CONTEXT_V2", chainId, manager, submissionManager, objectiveBindingContext, submissionId, pendingDecisionContext],
      ),
    );
    assert.equal(contextHash, "0xbd0f6be311daab9d11d429fd00805997c34189dc57fb3d140208822960e17fd4");

    const journalDigest = keccak256(
      coder.encode(
        ["string", "uint256", "address", "address", "bytes32", "bytes32", "bytes32", "bool", "address"],
        ["P42_OBJECTIVE_VERDICT_JOURNAL_V2", chainId, quorum, manager, guestElfSha256, programVKey, contextHash, true, proofBeneficiary],
      ),
    );
    assert.equal(journalDigest, "0xfa233a06c0c886e004200dbdd524aa970605fce4cafe77e2172c61512b8586c4");
  });

  it("matches the Kakeya claim-relative improvement witness across the Solidity ABI hash chain", () => {
    const solution = readFileSync(
      new URL("../../problems/arithmetic-kakeya/examples/kt-2x2-forcing.json", import.meta.url),
    );
    const solutionSha256 = `0x${createHash("sha256").update(solution).digest("hex")}`;
    assert.equal(solutionSha256, "0x031865755a17795bf2a4c65a24986589b6a8d10085d6a062fae5293c38a7f118");

    const chainId = 84_532n;
    const quorum = address("11");
    const manager = address("22");
    const submissionManager = address("33");
    const registry = address("44");
    const submissionId = 7n;
    const challenger = address("88");
    const reasonHash = repeat("99");
    const solutionCid = "ipfs://p42-kakeya-fixture";
    const transcriptUri = "ipfs://p42-kakeya-transcript";
    const guestElfSha256 = repeat("dd");
    const programVKey = repeat("ee");
    const claimedScoreAtoms = 1_750_000_000_000_000_000n;
    // The claimed score atoms equal the 7/4 seed atoms, so their canonical
    // uint256 difference is zero even though the guest verifies separately.
    const improvementAtoms = 0n;

    const revealInstanceHash = keccak256(
      coder.encode(
        ["address", "uint256", "uint256", "address", "bytes32", "bytes32", "bytes32", "int256", "uint256", "uint64"],
        [submissionManager, chainId, submissionId, address("66"), repeat("77"), solutionSha256, keccak256(toUtf8Bytes(solutionCid)), claimedScoreAtoms, improvementAtoms, 2_000_000_300n],
      ),
    );
    assert.equal(revealInstanceHash, "0xa1337e4b80f0d18cff14f78c595053311f208051a7e93c211c38f6b7dee61477");

    const challengeInstanceHash = keccak256(
      coder.encode(
        ["address", "uint256", "uint256", "bytes32", "address", "bytes32", "uint64", "uint64"],
        [manager, chainId, submissionId, revealInstanceHash, challenger, reasonHash, 2_000_000_100n, 2_000_000_200n],
      ),
    );
    const pendingDecisionContext = keccak256(
      coder.encode(
        ["bytes32", "bytes32", "address", "bytes32", "bool", "bytes32", "bytes32", "bytes32"],
        [challengeInstanceHash, revealInstanceHash, challenger, reasonHash, false, repeat("aa"), keccak256(toUtf8Bytes(transcriptUri)), repeat("bb")],
      ),
    );
    const objectiveBindingContext = keccak256(
      coder.encode(
        ["address", "uint256", "bytes32", "bytes32", "bytes32"],
        [registry, 4n, repeat("55"), guestElfSha256, programVKey],
      ),
    );
    const contextHash = keccak256(
      coder.encode(
        ["string", "uint256", "address", "address", "bytes32", "uint256", "bytes32"],
        ["P42_OBJECTIVE_CHALLENGE_CONTEXT_V2", chainId, manager, submissionManager, objectiveBindingContext, submissionId, pendingDecisionContext],
      ),
    );
    const journalDigest = keccak256(
      coder.encode(
        ["string", "uint256", "address", "address", "bytes32", "bytes32", "bytes32", "bool", "address"],
        ["P42_OBJECTIVE_VERDICT_JOURNAL_V2", chainId, quorum, manager, guestElfSha256, programVKey, contextHash, true, address("cc")],
      ),
    );
    assert.equal(journalDigest, "0xc35c5ff9ccf4047ef46dee665e7e679ee988c97315ea28cf25ce02f1fb15836f");
  });

  it("matches the isolated Rust/SP1 edges witness with signed maximize atoms", () => {
    const solution = readFileSync(
      new URL("../../problems/edges-vs-triangles/examples/rational-curve-sample.json", import.meta.url),
    );
    const solutionSha256 = `0x${createHash("sha256").update(solution).digest("hex")}`;
    assert.equal(solutionSha256, "0xa662d18c930fbb2c351ca5987e78113be30657a04615cbff87e4781745969214");

    const chainId = 84_532n;
    const quorum = address("11");
    const manager = address("22");
    const submissionManager = address("33");
    const registry = address("44");
    const submissionId = 7n;
    const challenger = address("88");
    const reasonHash = repeat("99");
    const solutionCid = "ipfs://p42-edges-objective-fixture";
    const transcriptUri = "ipfs://p42-edges-transcript";
    const guestElfSha256 = repeat("dd");
    const programVKey = repeat("ee");
    // Production maps maximize scores by negation before ceil quantization.
    const claimedScoreAtoms = 711_862_712_197_923_798n;

    const revealInstanceHash = keccak256(
      coder.encode(
        ["address", "uint256", "uint256", "address", "bytes32", "bytes32", "bytes32", "int256", "uint256", "uint64"],
        [submissionManager, chainId, submissionId, address("66"), repeat("77"), solutionSha256, keccak256(toUtf8Bytes(solutionCid)), claimedScoreAtoms, 1_000_000n, 2_000_000_300n],
      ),
    );
    assert.equal(revealInstanceHash, "0x68398c481438385e73a5f8ab2c0e09ad4577b46651a79924544eb458461e5513");
    const challengeInstanceHash = keccak256(
      coder.encode(
        ["address", "uint256", "uint256", "bytes32", "address", "bytes32", "uint64", "uint64"],
        [manager, chainId, submissionId, revealInstanceHash, challenger, reasonHash, 2_000_000_100n, 2_000_000_200n],
      ),
    );
    const pendingDecisionContext = keccak256(
      coder.encode(
        ["bytes32", "bytes32", "address", "bytes32", "bool", "bytes32", "bytes32", "bytes32"],
        [challengeInstanceHash, revealInstanceHash, challenger, reasonHash, false, repeat("aa"), keccak256(toUtf8Bytes(transcriptUri)), repeat("bb")],
      ),
    );
    const objectiveBindingContext = keccak256(
      coder.encode(
        ["address", "uint256", "bytes32", "bytes32", "bytes32"],
        [registry, 3n, repeat("55"), guestElfSha256, programVKey],
      ),
    );
    const contextHash = keccak256(
      coder.encode(
        ["string", "uint256", "address", "address", "bytes32", "uint256", "bytes32"],
        ["P42_OBJECTIVE_CHALLENGE_CONTEXT_V2", chainId, manager, submissionManager, objectiveBindingContext, submissionId, pendingDecisionContext],
      ),
    );
    const journalDigest = keccak256(
      coder.encode(
        ["string", "uint256", "address", "address", "bytes32", "bytes32", "bytes32", "bool", "address"],
        ["P42_OBJECTIVE_VERDICT_JOURNAL_V2", chainId, quorum, manager, guestElfSha256, programVKey, contextHash, true, address("cc")],
      ),
    );
    assert.equal(journalDigest, "0x7da3db058aa4c42dd54e590ce850e884c3504680dd29b25034046961f423033d");
  });
});
