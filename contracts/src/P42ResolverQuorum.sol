// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IP42QuorumChallengeManager {
    function owner() external view returns (address);
    function resolver() external view returns (address);
    function treasury() external view returns (address);
    function submissionManager() external view returns (address);
    function resolveFor(
        uint256 submissionId,
        bytes32 expectedChallengeInstanceHash,
        bool challengerWins,
        bytes32 transcriptHash,
        string calldata transcriptURI,
        bytes32 verdictHash,
        address resolverBondBeneficiary
    ) external payable;

    function slashResolverBond(
        uint256 submissionId,
        bytes32 expectedChallengeInstanceHash,
        bytes32 proofHash
    ) external;

    function applyObjectiveResolution(
        uint256 submissionId,
        bytes32 expectedChallengeInstanceHash,
        bool correctedChallengerWins,
        bytes32 proofHash,
        address proofBeneficiary
    ) external;

    function objectiveProofContext(uint256 submissionId, bytes32 expectedChallengeInstanceHash)
        external
        view
        returns (bytes32 contextHash, bool pendingChallengerWins);

    function objectiveBinding()
        external
        view
        returns (address registry, uint256 problemId, bytes32 packageHash, bytes32 programId);

    function resolverDecisionBondWei() external view returns (uint256);
    function claimBond() external;
}

interface IP42ObjectiveVerifierGateway {
    function verify(bytes32 programId, bytes32 journalDigest, bytes calldata proof) external view returns (bool);
}

interface IP42QuorumSubmissionManager {
    function challengeManager() external view returns (address);
}

interface IP42CanonicalManagerFactory {
    function isCanonicalManager(address manager) external view returns (bool);
}

/// @notice Immutable EIP-712 threshold authority shared by the ten P42 boards.
/// Managers are registered during deployment and irreversibly frozen before use.
contract P42ResolverQuorum {
    error NotOwner();
    error BadOwner();
    error BadSigner();
    error BadThreshold();
    error UnknownSignerEpoch();
    error StaleSignerEpoch();
    error RotationCooldownActive();
    error BadManager();
    error WrongManagerCount(uint256 have, uint256 required);
    error Paused();
    error PauseAlreadyActive();
    error PauseCooldownActive();
    error BadDecisionBinding();
    error DecisionExpired();
    error NonceAlreadyUsed();
    error ChallengeAlreadyDecided();
    error BadSignature();
    error SignersNotStrictlySorted();
    error InsufficientSignatures(uint256 have, uint256 required);
    error TranscriptURIMismatch();
    error NotSigner();
    error UnexpectedValue();
    error InsufficientStake(uint256 required, uint256 available);
    error NotEquivocation();
    error EquivocationAlreadyProven();
    error BadObjectiveVerifier();
    error BadObjectiveProgram();
    error BadObjectiveProof();
    error ObjectiveOutcomeNotContradictory();
    error FraudProofBeneficiaryZero();
    error ObjectiveProofReentrancy();

    uint256 public constant REQUIRED_MANAGER_COUNT = 10;
    // Set from the independently compiled P42ChallengeManagerFactory runtime.
    bytes32 public constant CANONICAL_MANAGER_FACTORY_CODEHASH =
        0x16a202c30ad99ce66322755ee79038508f3d2303684f8fac83a420a369613876;
    bytes32 public constant DECISION_TYPEHASH = keccak256(
        "Decision(uint256 chainId,address adapter,address manager,uint256 submissionId,bytes32 challengeInstanceHash,bool challengerWins,bytes32 transcriptHash,bytes32 transcriptURIHash,bytes32 verdictHash,address bondBeneficiary,uint256 nonce,uint64 expiry,uint64 signerEpoch)"
    );
    uint64 public constant PAUSE_DURATION = 24 hours;
    uint64 public constant PAUSE_COOLDOWN = 24 hours;
    uint64 public constant SIGNER_ROTATION_COOLDOWN = 7 days;
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("P42ResolverQuorum");
    bytes32 private constant VERSION_HASH = keccak256("1");
    // secp256k1n / 2, rejecting malleable high-s signatures.
    uint256 private constant SECP256K1N_HALF =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct Decision {
        uint256 chainId;
        address adapter;
        address manager;
        uint256 submissionId;
        bytes32 challengeInstanceHash;
        bool challengerWins;
        bytes32 transcriptHash;
        bytes32 transcriptURIHash;
        bytes32 verdictHash;
        address bondBeneficiary;
        uint256 nonce;
        uint64 expiry;
        uint64 signerEpoch;
    }

    struct ObjectiveClaim {
        address manager;
        uint256 submissionId;
        bytes32 challengeInstanceHash;
        bool correctedChallengerWins;
        address proofBeneficiary;
    }

    address public immutable owner;
    address public immutable expectedTreasury;
    uint256 public immutable expectedDecisionBondWei;
    address public immutable managerFactory;
    address public immutable objectiveVerifier;
    bytes32 public immutable objectiveVerifierCodehash;
    uint256 public threshold;
    uint64 public signerEpoch;
    address[] private _signers;
    mapping(address => bool) public isSigner;
    mapping(uint64 => address[]) private _epochSigners;
    mapping(uint64 => mapping(address => bool)) private _isEpochSigner;
    mapping(uint64 => uint256) public epochThreshold;
    mapping(address => bool) public isManager;
    mapping(address => bytes32) public objectiveProgramIdOf;
    address[] private _managers;
    bool public constant managersFrozen = true;
    uint64 public pauseUntil;
    uint64 public pauseCooldownUntil;
    uint64 public nextSignerRotationAt;
    bool private _provingObjective;

    mapping(address => mapping(uint256 => bool)) public nonceUsed;
    mapping(address => mapping(bytes32 => bool)) public challengeDecided;
    mapping(bytes32 => bool) public equivocationProven;

    event PauseSet(bool paused, uint64 pauseUntil, uint64 cooldownUntil);
    event SignerSetRotated(uint64 indexed signerEpoch, uint256 threshold, address[] signers);
    event DecisionForwarded(
        address indexed manager,
        uint256 indexed submissionId,
        bytes32 indexed challengeInstanceHash,
        bytes32 decisionDigest,
        uint256 nonce,
        bool challengerWins
    );
    event EquivocationProven(
        address indexed manager,
        uint256 indexed submissionId,
        bytes32 indexed challengeInstanceHash,
        bytes32 proofHash,
        bytes32 firstDecisionHash,
        bytes32 secondDecisionHash
    );
    event ObjectiveFraudProven(
        address indexed manager,
        uint256 indexed submissionId,
        bytes32 indexed challengeInstanceHash,
        bytes32 proofHash,
        bytes32 journalDigest,
        bool correctedChallengerWins,
        address proofBeneficiary
    );
    event StakeFunded(address indexed signer, uint256 amount, uint256 balance);
    event StakeReclaimed(address indexed manager, uint256 balance);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(
        address owner_,
        address expectedTreasury_,
        uint256 expectedDecisionBondWei_,
        address managerFactory_,
        address[] memory signers_,
        uint256 threshold_,
        address[] memory managers_,
        address objectiveVerifier_,
        bytes32 objectiveVerifierCodehash_
    ) {
        if (owner_ == address(0) || expectedTreasury_ == address(0)) revert BadOwner();
        if (signers_.length < 3 || signers_.length > 5) revert BadSigner();
        if (threshold_ <= signers_.length / 2 || threshold_ > signers_.length) revert BadThreshold();
        if (expectedDecisionBondWei_ == 0) revert BadDecisionBinding();
        owner = owner_;
        expectedTreasury = expectedTreasury_;
        expectedDecisionBondWei = expectedDecisionBondWei_;
        if (
            managerFactory_ == address(0)
                || managerFactory_.codehash != CANONICAL_MANAGER_FACTORY_CODEHASH
        ) revert BadManager();
        managerFactory = managerFactory_;
        if (
            objectiveVerifier_ == address(0) || objectiveVerifier_.code.length == 0
                || objectiveVerifierCodehash_ == bytes32(0) || objectiveVerifier_.codehash != objectiveVerifierCodehash_
        ) {
            revert BadObjectiveVerifier();
        }
        objectiveVerifier = objectiveVerifier_;
        objectiveVerifierCodehash = objectiveVerifierCodehash_;
        _installSignerSet(1, signers_, threshold_);
        nextSignerRotationAt = uint64(block.timestamp) + SIGNER_ROTATION_COOLDOWN;
        if (managers_.length != REQUIRED_MANAGER_COUNT) {
            revert WrongManagerCount(managers_.length, REQUIRED_MANAGER_COUNT);
        }
        for (uint256 i; i < managers_.length; ++i) {
            _addCanonicalManager(managers_[i]);
        }
    }

    receive() external payable {
        if (!isManager[msg.sender]) revert BadManager();
    }

    function fundStake() external payable {
        if (!isSigner[msg.sender]) revert NotSigner();
        if (msg.value == 0) revert UnexpectedValue();
        emit StakeFunded(msg.sender, msg.value, address(this).balance);
    }

    function signerCount() external view returns (uint256) {
        return _signers.length;
    }

    function signerAt(uint256 index) external view returns (address) {
        return _signers[index];
    }

    function epochSignerCount(uint64 epoch) external view returns (uint256) {
        return _epochSigners[epoch].length;
    }

    function epochSignerAt(uint64 epoch, uint256 index) external view returns (address) {
        return _epochSigners[epoch][index];
    }

    function isEpochSigner(uint64 epoch, address signer) external view returns (bool) {
        return _isEpochSigner[epoch][signer];
    }

    function managerCount() external view returns (uint256) {
        return _managers.length;
    }

    function managerAt(uint256 index) external view returns (address) {
        return _managers[index];
    }

    function _addCanonicalManager(address manager) private {
        if (manager == address(0) || manager.code.length == 0) revert BadManager();
        if (isManager[manager] || !IP42CanonicalManagerFactory(managerFactory).isCanonicalManager(manager)) {
            revert BadManager();
        }
        IP42QuorumChallengeManager candidate = IP42QuorumChallengeManager(manager);
        address submissions = candidate.submissionManager();
        (address registry, uint256 problemId, bytes32 packageHash, bytes32 programId) = candidate.objectiveBinding();
        if (
            candidate.owner() != owner || candidate.resolver() != address(this)
                || candidate.treasury() != expectedTreasury
                || candidate.resolverDecisionBondWei() != expectedDecisionBondWei
                || submissions.code.length == 0
                || registry == address(0) || problemId == 0 || packageHash == bytes32(0) || programId == bytes32(0)
                || IP42QuorumSubmissionManager(submissions).challengeManager() != manager
        ) revert BadManager();
        isManager[manager] = true;
        objectiveProgramIdOf[manager] = programId;
        _managers.push(manager);
    }

    function rotateSigners(address[] calldata signers_, uint256 threshold_) external onlyOwner {
        if (block.timestamp < nextSignerRotationAt) revert RotationCooldownActive();
        uint64 nextEpoch = signerEpoch + 1;
        _installSignerSet(nextEpoch, signers_, threshold_);
        nextSignerRotationAt = uint64(block.timestamp) + SIGNER_ROTATION_COOLDOWN;
    }

    function _installSignerSet(uint64 epoch, address[] memory signers_, uint256 threshold_) private {
        if (signers_.length < 3 || signers_.length > 5) revert BadSigner();
        if (threshold_ <= signers_.length / 2 || threshold_ > signers_.length) revert BadThreshold();
        for (uint256 i; i < _signers.length; ++i) isSigner[_signers[i]] = false;
        delete _signers;
        for (uint256 i; i < signers_.length; ++i) {
            address signer = signers_[i];
            if (signer == address(0) || _isEpochSigner[epoch][signer]) revert BadSigner();
            isSigner[signer] = true;
            _isEpochSigner[epoch][signer] = true;
            _signers.push(signer);
            _epochSigners[epoch].push(signer);
        }
        signerEpoch = epoch;
        threshold = threshold_;
        epochThreshold[epoch] = threshold_;
        emit SignerSetRotated(epoch, threshold_, signers_);
    }

    function paused() public view returns (bool) {
        return block.timestamp < pauseUntil;
    }

    function setPaused(bool paused_) external onlyOwner {
        if (paused_) {
            if (paused()) revert PauseAlreadyActive();
            if (block.timestamp < pauseCooldownUntil) revert PauseCooldownActive();
            pauseUntil = uint64(block.timestamp) + PAUSE_DURATION;
            pauseCooldownUntil = pauseUntil + PAUSE_COOLDOWN;
        } else {
            pauseUntil = uint64(block.timestamp);
        }
        emit PauseSet(paused_, pauseUntil, pauseCooldownUntil);
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function decisionStructHash(Decision calldata decision) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                DECISION_TYPEHASH,
                decision.chainId,
                decision.adapter,
                decision.manager,
                decision.submissionId,
                decision.challengeInstanceHash,
                decision.challengerWins,
                decision.transcriptHash,
                decision.transcriptURIHash,
                decision.verdictHash,
                decision.bondBeneficiary,
                decision.nonce,
                decision.expiry,
                decision.signerEpoch
            )
        );
    }

    function decisionDigest(Decision calldata decision) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), decisionStructHash(decision)));
    }

    function resolve(Decision calldata decision, string calldata transcriptURI, bytes[] calldata signatures)
        external
        payable
    {
        if (paused()) revert Paused();
        _requireDecisionBinding(decision, true);
        if (msg.value != 0) revert UnexpectedValue();
        if (keccak256(bytes(transcriptURI)) != decision.transcriptURIHash) revert TranscriptURIMismatch();
        if (nonceUsed[decision.manager][decision.nonce]) revert NonceAlreadyUsed();
        if (challengeDecided[decision.manager][decision.challengeInstanceHash]) revert ChallengeAlreadyDecided();

        bytes32 digest = decisionDigest(decision);
        _requireQuorum(decision.signerEpoch, digest, signatures);
        // Effects precede the manager call; a manager revert atomically restores them.
        nonceUsed[decision.manager][decision.nonce] = true;
        challengeDecided[decision.manager][decision.challengeInstanceHash] = true;

        _forwardDecision(decision, transcriptURI);
        emit DecisionForwarded(
            decision.manager,
            decision.submissionId,
            decision.challengeInstanceHash,
            digest,
            decision.nonce,
            decision.challengerWins
        );
    }

    function _forwardDecision(Decision calldata decision, string calldata transcriptURI) private {
        uint256 decisionBond = IP42QuorumChallengeManager(decision.manager).resolverDecisionBondWei();
        if (address(this).balance < decisionBond) revert InsufficientStake(decisionBond, address(this).balance);
        IP42QuorumChallengeManager(decision.manager).resolveFor{value: decisionBond}(
            decision.submissionId,
            decision.challengeInstanceHash,
            decision.challengerWins,
            decision.transcriptHash,
            transcriptURI,
            decision.verdictHash,
            address(this)
        );
    }

    /// @notice Restores a successfully released decision bond to the shared
    /// slashable stake. The manager transfers only this adapter's claim.
    function reclaimStake(address manager) external {
        if (!isManager[manager]) revert BadManager();
        IP42QuorumChallengeManager(manager).claimBond();
        emit StakeReclaimed(manager, address(this).balance);
    }

    /// @notice Anyone may prove that the quorum signed two different decisions
    /// for one challenge instance. The proof hash is order-independent.
    function proveEquivocation(
        Decision calldata first,
        bytes[] calldata firstSignatures,
        Decision calldata second,
        bytes[] calldata secondSignatures
    ) external {
        _requireDecisionBinding(first, false);
        _requireDecisionBinding(second, false);
        if (
            first.manager != second.manager || first.submissionId != second.submissionId
                || first.challengeInstanceHash != second.challengeInstanceHash
                || first.signerEpoch != second.signerEpoch
        ) revert NotEquivocation();

        bytes32 firstStructHash = decisionStructHash(first);
        bytes32 secondStructHash = decisionStructHash(second);
        if (firstStructHash == secondStructHash || _decisionContentHash(first) == _decisionContentHash(second)) {
            revert NotEquivocation();
        }
        _requireQuorum(first.signerEpoch, decisionDigest(first), firstSignatures);
        _requireQuorum(second.signerEpoch, decisionDigest(second), secondSignatures);

        (bytes32 low, bytes32 high) = firstStructHash < secondStructHash
            ? (firstStructHash, secondStructHash)
            : (secondStructHash, firstStructHash);
        bytes32 proofHash = keccak256(
            abi.encode("P42_RESOLVER_EQUIVOCATION_V1", block.chainid, address(this), first.manager, first.submissionId, first.challengeInstanceHash, low, high)
        );
        if (equivocationProven[proofHash]) revert EquivocationAlreadyProven();
        equivocationProven[proofHash] = true;
        IP42QuorumChallengeManager(first.manager).slashResolverBond(
            first.submissionId, first.challengeInstanceHash, proofHash
        );
        emit EquivocationProven(
            first.manager,
            first.submissionId,
            first.challengeInstanceHash,
            proofHash,
            firstStructHash,
            secondStructHash
        );
    }

    /// @notice Permissionlessly proves that a pending quorum verdict is wrong.
    /// The immutable board program verifies the exact challenge context, and
    /// the proof beneficiary is journal-bound so a copied proof cannot redirect
    /// the resolver-bond reward.
    function proveObjectiveFraud(ObjectiveClaim calldata claim, bytes calldata proof) external {
        if (_provingObjective) revert ObjectiveProofReentrancy();
        _provingObjective = true;
        if (!isManager[claim.manager]) revert BadManager();
        if (claim.proofBeneficiary == address(0)) revert FraudProofBeneficiaryZero();
        if (objectiveVerifier.codehash != objectiveVerifierCodehash) revert BadObjectiveVerifier();

        (bytes32 contextHash, bool pendingChallengerWins) = IP42QuorumChallengeManager(claim.manager)
            .objectiveProofContext(claim.submissionId, claim.challengeInstanceHash);
        if (claim.correctedChallengerWins == pendingChallengerWins) {
            revert ObjectiveOutcomeNotContradictory();
        }

        bytes32 programId = objectiveProgramIdOf[claim.manager];
        bytes32 journalDigest = keccak256(
            abi.encode(
                "P42_OBJECTIVE_VERDICT_JOURNAL_V1",
                block.chainid,
                address(this),
                claim.manager,
                programId,
                contextHash,
                claim.correctedChallengerWins,
                claim.proofBeneficiary
            )
        );
        if (!IP42ObjectiveVerifierGateway(objectiveVerifier).verify(programId, journalDigest, proof)) {
            revert BadObjectiveProof();
        }
        bytes32 proofHash = keccak256(
            abi.encode("P42_OBJECTIVE_FRAUD_PROOF_V1", programId, journalDigest, keccak256(proof))
        );
        IP42QuorumChallengeManager(claim.manager).applyObjectiveResolution(
            claim.submissionId,
            claim.challengeInstanceHash,
            claim.correctedChallengerWins,
            proofHash,
            claim.proofBeneficiary
        );
        emit ObjectiveFraudProven(
            claim.manager,
            claim.submissionId,
            claim.challengeInstanceHash,
            proofHash,
            journalDigest,
            claim.correctedChallengerWins,
            claim.proofBeneficiary
        );
        _provingObjective = false;
    }

    function _requireDecisionBinding(Decision calldata decision, bool enforceExpiry) private view {
        if (
            decision.chainId != block.chainid || decision.adapter != address(this) || !isManager[decision.manager]
                || decision.manager == address(0) || decision.submissionId == 0
                || decision.challengeInstanceHash == bytes32(0) || decision.transcriptHash == bytes32(0)
                || decision.transcriptURIHash == bytes32(0) || decision.verdictHash == bytes32(0)
                || decision.bondBeneficiary != address(this) || epochThreshold[decision.signerEpoch] == 0
        ) revert BadDecisionBinding();
        if (enforceExpiry && decision.signerEpoch != signerEpoch) revert StaleSignerEpoch();
        if (enforceExpiry && block.timestamp > decision.expiry) revert DecisionExpired();
    }

    function _decisionContentHash(Decision calldata decision) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                decision.chainId,
                decision.adapter,
                decision.manager,
                decision.submissionId,
                decision.challengeInstanceHash,
                decision.challengerWins,
                decision.transcriptHash,
                decision.transcriptURIHash,
                decision.verdictHash,
                decision.bondBeneficiary
            )
        );
    }

    function _requireQuorum(uint64 epoch, bytes32 digest, bytes[] calldata signatures) private view {
        uint256 required = epochThreshold[epoch];
        if (required == 0) revert UnknownSignerEpoch();
        if (signatures.length < required) revert InsufficientSignatures(signatures.length, required);
        address previous;
        uint256 valid;
        for (uint256 i; i < signatures.length; ++i) {
            address recovered = _recover(digest, signatures[i]);
            if (recovered <= previous) revert SignersNotStrictlySorted();
            previous = recovered;
            if (!_isEpochSigner[epoch][recovered]) revert BadSignature();
            ++valid;
        }
        if (valid < required) revert InsufficientSignatures(valid, required);
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address recovered) {
        if (signature.length != 65) revert BadSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > SECP256K1N_HALF || (v != 27 && v != 28)) revert BadSignature();
        recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0)) revert BadSignature();
    }
}
