// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

interface IEncryptedLocalTallyVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[11] calldata publicSignals
    ) external view returns (bool);
}

interface IPartialDecryptionVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[6] calldata publicSignals
    ) external view returns (bool);
}

interface ITrusteeRegistryVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[11] calldata publicSignals
    ) external view returns (bool);
}

contract ZKLocalTallyIntegrity is Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    uint8 public constant CANDIDATE_COUNT = 2;
    uint8 public constant TRUSTEE_COUNT = 3;
    uint8 public constant TRUSTEE_THRESHOLD = 2;

    uint256 private constant BABYJUB_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant BABYJUB_A = 168700;
    uint256 private constant BABYJUB_D = 168696;

    enum Phase {
        Registration,
        Submission,
        ReadyForDecryption,
        Cancelled
    }

    struct AuthorityConfig {
        bool registered;
        uint256 localElectorateSize;
        bool submitted;
    }

    struct TrusteeConfig {
        bool registered;
        uint256 shareIndex;
        uint256 publicShareX;
        uint256 publicShareY;
    }

    struct Ciphertext {
        uint256 c1x;
        uint256 c1y;
        uint256 c2x;
        uint256 c2y;
    }

    struct SubmissionRecord {
        bool submitted;
        Ciphertext[2] ciphertexts;
        bytes32 transcriptCommitment;
        uint64 blockTimestamp;
    }

    struct PartialDecryptionRecord {
        bool submitted;
        uint256 shareX;
        uint256 shareY;
        uint64 blockTimestamp;
    }

    IEncryptedLocalTallyVerifier public immutable encryptedLocalTallyVerifier;
    IPartialDecryptionVerifier public immutable partialDecryptionVerifier;
    ITrusteeRegistryVerifier public immutable trusteeRegistryVerifier;

    Phase public phase;
    uint256 public electionId;
    uint64 public submissionDeadline;
    uint256 public snapshotAuthorityCount;
    uint256 public acceptedSubmissionCount;
    uint256 public snapshotTrusteeCount;
    uint256 public decryptionThreshold;
    uint256 public publicKeyX;
    uint256 public publicKeyY;
    bool public trusteeRegistryVerified;

    address[] private authorityList;
    mapping(address => AuthorityConfig) private authorities;
    mapping(address => SubmissionRecord) private submissions;
    Ciphertext[CANDIDATE_COUNT] private aggregateCiphertexts;

    address[] private trusteeList;
    mapping(address => TrusteeConfig) private trustees;
    mapping(uint256 => bool) private trusteeShareIndexUsed;
    mapping(uint8 => mapping(address => PartialDecryptionRecord)) private partialDecryptions;
    mapping(uint8 => uint256) public acceptedPartialDecryptionCount;

    event AuthorityRegistered(address indexed authority, uint256 localElectorateSize);
    event AuthorityRemoved(address indexed authority);
    event TrusteeRegistered(address indexed trustee, uint256 shareIndex, uint256 publicShareX, uint256 publicShareY);
    event TrusteeRemoved(address indexed trustee, uint256 shareIndex);
    event ElectionStarted(
        uint256 indexed electionId,
        uint64 submissionDeadline,
        uint256 publicKeyX,
        uint256 publicKeyY,
        uint256 authorityCount,
        uint256 trusteeCount,
        uint256 decryptionThreshold
    );
    event EncryptedLocalTallyAccepted(
        address indexed authority,
        bytes32 transcriptCommitment,
        bytes32 signedSubmissionDigest
    );
    event DecryptionReady(uint256 indexed electionId, uint256 acceptedSubmissionCount);
    event PartialDecryptionAccepted(
        uint8 indexed candidateIndex,
        address indexed trustee,
        uint256 shareIndex,
        uint256 acceptedShareCount
    );
    event DecryptionThresholdReached(uint8 indexed candidateIndex, uint256 decryptionThreshold);
    event ElectionCancelled(uint8 cancelledFromPhase, uint256 progressCount, uint256 expectedAuthorityCount);

    constructor(
        address encryptedLocalTallyVerifierAddress,
        address partialDecryptionVerifierAddress,
        address trusteeRegistryVerifierAddress
    ) Ownable(msg.sender) {
        require(encryptedLocalTallyVerifierAddress != address(0), "Zero tally verifier");
        require(partialDecryptionVerifierAddress != address(0), "Zero decrypt verifier");
        require(trusteeRegistryVerifierAddress != address(0), "Zero setup verifier");

        encryptedLocalTallyVerifier = IEncryptedLocalTallyVerifier(encryptedLocalTallyVerifierAddress);
        partialDecryptionVerifier = IPartialDecryptionVerifier(partialDecryptionVerifierAddress);
        trusteeRegistryVerifier = ITrusteeRegistryVerifier(trusteeRegistryVerifierAddress);
        phase = Phase.Registration;
        _resetAggregateCiphertexts();
    }

    modifier onlyInPhase(Phase expected) {
        require(phase == expected, "Wrong phase");
        _;
    }

    function registerAuthority(address authority, uint256 localElectorateSize)
        external
        onlyOwner
        onlyInPhase(Phase.Registration)
    {
        require(authority != address(0), "Zero address");
        require(!authorities[authority].registered, "Already registered");
        require(localElectorateSize > 0, "Zero electorate");

        authorities[authority] = AuthorityConfig({
            registered: true,
            localElectorateSize: localElectorateSize,
            submitted: false
        });
        authorityList.push(authority);

        emit AuthorityRegistered(authority, localElectorateSize);
    }

    function removeAuthority(address authority)
        external
        onlyOwner
        onlyInPhase(Phase.Registration)
    {
        require(authorities[authority].registered, "Not registered");
        delete authorities[authority];

        uint256 length = authorityList.length;
        for (uint256 i = 0; i < length; i++) {
            if (authorityList[i] == authority) {
                authorityList[i] = authorityList[length - 1];
                authorityList.pop();
                emit AuthorityRemoved(authority);
                return;
            }
        }

        revert("Authority list mismatch");
    }

    function registerTrustee(address trustee, uint256 shareIndex, uint256 publicShareX, uint256 publicShareY)
        external
        onlyOwner
        onlyInPhase(Phase.Registration)
    {
        require(trustee != address(0), "Zero address");
        require(!trustees[trustee].registered, "Already registered");
        require(shareIndex > 0, "Zero share index");
        require(!trusteeShareIndexUsed[shareIndex], "Share index used");
        require(publicShareX != 0 || publicShareY != 0, "Zero public share");

        trustees[trustee] = TrusteeConfig({
            registered: true,
            shareIndex: shareIndex,
            publicShareX: publicShareX,
            publicShareY: publicShareY
        });
        trusteeShareIndexUsed[shareIndex] = true;
        trusteeList.push(trustee);

        emit TrusteeRegistered(trustee, shareIndex, publicShareX, publicShareY);
    }

    function removeTrustee(address trustee)
        external
        onlyOwner
        onlyInPhase(Phase.Registration)
    {
        TrusteeConfig storage config = trustees[trustee];
        require(config.registered, "Not registered");
        uint256 shareIndex = config.shareIndex;

        delete trusteeShareIndexUsed[shareIndex];
        delete trustees[trustee];

        uint256 length = trusteeList.length;
        for (uint256 i = 0; i < length; i++) {
            if (trusteeList[i] == trustee) {
                trusteeList[i] = trusteeList[length - 1];
                trusteeList.pop();
                emit TrusteeRemoved(trustee, shareIndex);
                return;
            }
        }

        revert("Trustee list mismatch");
    }

    function startElection(
        uint64 _submissionDeadline,
        uint256 _publicKeyX,
        uint256 _publicKeyY,
        uint256 _decryptionThreshold,
        uint256[2] calldata setupA,
        uint256[2][2] calldata setupB,
        uint256[2] calldata setupC,
        uint256[11] calldata setupSignals
    ) external onlyOwner onlyInPhase(Phase.Registration) {
        require(authorityList.length > 0, "No authorities");
        require(trusteeList.length == TRUSTEE_COUNT, "Artifact expects 3 trustees");
        require(_submissionDeadline > block.timestamp, "Deadline in past");
        require(_publicKeyX != 0 || _publicKeyY != 0, "Zero public key");
        require(_decryptionThreshold == TRUSTEE_THRESHOLD, "Artifact expects 2-of-3");

        _assertTrusteeSetupSignals(_publicKeyX, _publicKeyY, setupSignals);
        require(
            trusteeRegistryVerifier.verifyProof(setupA, setupB, setupC, setupSignals),
            "Invalid trustee setup proof"
        );

        electionId += 1;
        snapshotAuthorityCount = authorityList.length;
        snapshotTrusteeCount = trusteeList.length;
        submissionDeadline = _submissionDeadline;
        publicKeyX = _publicKeyX;
        publicKeyY = _publicKeyY;
        decryptionThreshold = _decryptionThreshold;
        acceptedSubmissionCount = 0;
        acceptedPartialDecryptionCount[0] = 0;
        acceptedPartialDecryptionCount[1] = 0;
        trusteeRegistryVerified = true;
        _resetAggregateCiphertexts();
        phase = Phase.Submission;

        emit ElectionStarted(
            electionId,
            _submissionDeadline,
            _publicKeyX,
            _publicKeyY,
            snapshotAuthorityCount,
            snapshotTrusteeCount,
            _decryptionThreshold
        );
    }

    function submitEncryptedLocalTally(
        Ciphertext[2] calldata ciphertexts,
        bytes calldata authoritySignature,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[11] calldata publicSignals
    ) external onlyInPhase(Phase.Submission) {
        require(block.timestamp <= submissionDeadline, "Submission closed");

        AuthorityConfig storage config = authorities[msg.sender];
        require(config.registered, "Authority not authorized");
        require(!config.submitted, "Already submitted");

        bytes32 submissionDigest = getSubmissionDigest(msg.sender, config.localElectorateSize, ciphertexts);
        address recoveredSigner = submissionDigest.toEthSignedMessageHash().recover(authoritySignature);
        require(recoveredSigner == msg.sender, "Bad submission signature");

        _assertEncryptedTallyPublicSignals(config.localElectorateSize, ciphertexts, publicSignals);
        require(
            encryptedLocalTallyVerifier.verifyProof(pA, pB, pC, publicSignals),
            "Invalid proof"
        );

        config.submitted = true;
        acceptedSubmissionCount += 1;

        SubmissionRecord storage submission = submissions[msg.sender];
        submission.submitted = true;
        submission.ciphertexts[0] = ciphertexts[0];
        submission.ciphertexts[1] = ciphertexts[1];
        submission.transcriptCommitment = keccak256(
            abi.encode(
                ciphertexts[0].c1x,
                ciphertexts[0].c1y,
                ciphertexts[0].c2x,
                ciphertexts[0].c2y,
                ciphertexts[1].c1x,
                ciphertexts[1].c1y,
                ciphertexts[1].c2x,
                ciphertexts[1].c2y
            )
        );
        submission.blockTimestamp = uint64(block.timestamp);

        _accumulateCiphertexts(ciphertexts);

        emit EncryptedLocalTallyAccepted(msg.sender, submission.transcriptCommitment, submissionDigest);

        if (acceptedSubmissionCount == snapshotAuthorityCount) {
            phase = Phase.ReadyForDecryption;
            emit DecryptionReady(electionId, acceptedSubmissionCount);
        }
    }

    function submitPartialDecryption(
        uint8 candidateIndex,
        uint256 shareX,
        uint256 shareY,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[6] calldata publicSignals
    ) external onlyInPhase(Phase.ReadyForDecryption) {
        require(candidateIndex < CANDIDATE_COUNT, "Wrong candidate");

        TrusteeConfig storage trustee = trustees[msg.sender];
        require(trustee.registered, "Trustee not authorized");

        PartialDecryptionRecord storage record = partialDecryptions[candidateIndex][msg.sender];
        require(!record.submitted, "Share already submitted");

        _assertPartialDecryptionPublicSignals(candidateIndex, trustee, shareX, shareY, publicSignals);
        require(
            partialDecryptionVerifier.verifyProof(pA, pB, pC, publicSignals),
            "Invalid decryption proof"
        );

        record.submitted = true;
        record.shareX = shareX;
        record.shareY = shareY;
        record.blockTimestamp = uint64(block.timestamp);

        acceptedPartialDecryptionCount[candidateIndex] += 1;
        emit PartialDecryptionAccepted(
            candidateIndex,
            msg.sender,
            trustee.shareIndex,
            acceptedPartialDecryptionCount[candidateIndex]
        );

        if (acceptedPartialDecryptionCount[candidateIndex] == decryptionThreshold) {
            emit DecryptionThresholdReached(candidateIndex, decryptionThreshold);
        }
    }

    function cancelIfSubmissionExpired() external onlyInPhase(Phase.Submission) {
        require(block.timestamp > submissionDeadline, "Deadline not reached");
        require(acceptedSubmissionCount < snapshotAuthorityCount, "All submissions accepted");

        phase = Phase.Cancelled;
        emit ElectionCancelled(uint8(Phase.Submission), acceptedSubmissionCount, snapshotAuthorityCount);
    }

    function isAuthority(address authority) external view returns (bool) {
        return authorities[authority].registered;
    }

    function isTrustee(address trustee) external view returns (bool) {
        return trustees[trustee].registered;
    }

    function getAuthorityList() external view returns (address[] memory) {
        return authorityList;
    }

    function getTrusteeList() external view returns (address[] memory) {
        return trusteeList;
    }

    function getAuthorityConfig(address authority)
        external
        view
        returns (bool registered, uint256 localElectorateSize, bool submitted)
    {
        AuthorityConfig storage config = authorities[authority];
        return (config.registered, config.localElectorateSize, config.submitted);
    }

    function getTrusteeConfig(address trustee)
        external
        view
        returns (bool registered, uint256 shareIndex, uint256 publicShareX, uint256 publicShareY)
    {
        TrusteeConfig storage config = trustees[trustee];
        return (config.registered, config.shareIndex, config.publicShareX, config.publicShareY);
    }

    function getSubmission(address authority) external view returns (SubmissionRecord memory) {
        return submissions[authority];
    }

    function getAggregateCiphertext(uint8 candidateIndex) external view returns (Ciphertext memory) {
        require(candidateIndex < CANDIDATE_COUNT, "Wrong candidate");
        return aggregateCiphertexts[candidateIndex];
    }

    function getPartialDecryption(uint8 candidateIndex, address trustee)
        external
        view
        returns (PartialDecryptionRecord memory)
    {
        require(candidateIndex < CANDIDATE_COUNT, "Wrong candidate");
        return partialDecryptions[candidateIndex][trustee];
    }

    function getSubmissionDigest(
        address authority,
        uint256 localElectorateSize,
        Ciphertext[2] calldata ciphertexts
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                address(this),
                block.chainid,
                electionId,
                authority,
                localElectorateSize,
                ciphertexts[0].c1x,
                ciphertexts[0].c1y,
                ciphertexts[0].c2x,
                ciphertexts[0].c2y,
                ciphertexts[1].c1x,
                ciphertexts[1].c1y,
                ciphertexts[1].c2x,
                ciphertexts[1].c2y
            )
        );
    }

    function _assertEncryptedTallyPublicSignals(
        uint256 localElectorateSize,
        Ciphertext[2] calldata ciphertexts,
        uint256[11] calldata publicSignals
    ) internal view {
        require(publicSignals[0] == localElectorateSize, "Wrong electorate");
        require(publicSignals[1] == publicKeyX, "Wrong pk x");
        require(publicSignals[2] == publicKeyY, "Wrong pk y");

        require(publicSignals[3] == ciphertexts[0].c1x, "Wrong c1x[0]");
        require(publicSignals[4] == ciphertexts[1].c1x, "Wrong c1x[1]");
        require(publicSignals[5] == ciphertexts[0].c1y, "Wrong c1y[0]");
        require(publicSignals[6] == ciphertexts[1].c1y, "Wrong c1y[1]");
        require(publicSignals[7] == ciphertexts[0].c2x, "Wrong c2x[0]");
        require(publicSignals[8] == ciphertexts[1].c2x, "Wrong c2x[1]");
        require(publicSignals[9] == ciphertexts[0].c2y, "Wrong c2y[0]");
        require(publicSignals[10] == ciphertexts[1].c2y, "Wrong c2y[1]");
    }

    function _assertTrusteeSetupSignals(
        uint256 _publicKeyX,
        uint256 _publicKeyY,
        uint256[11] calldata publicSignals
    ) internal view {
        require(publicSignals[0] == _publicKeyX, "Wrong setup pk x");
        require(publicSignals[1] == _publicKeyY, "Wrong setup pk y");

        for (uint256 i = 0; i < TRUSTEE_COUNT; i++) {
            TrusteeConfig storage trustee = trustees[trusteeList[i]];
            require(publicSignals[2 + i] == trustee.shareIndex, "Wrong setup share index");
            require(publicSignals[5 + i] == trustee.publicShareX, "Wrong setup share x");
            require(publicSignals[8 + i] == trustee.publicShareY, "Wrong setup share y");
        }
    }

    function _assertPartialDecryptionPublicSignals(
        uint8 candidateIndex,
        TrusteeConfig storage trustee,
        uint256 shareX,
        uint256 shareY,
        uint256[6] calldata publicSignals
    ) internal view {
        Ciphertext storage aggregateCiphertext = aggregateCiphertexts[candidateIndex];

        require(publicSignals[0] == trustee.publicShareX, "Wrong public share x");
        require(publicSignals[1] == trustee.publicShareY, "Wrong public share y");
        require(publicSignals[2] == aggregateCiphertext.c1x, "Wrong aggregate c1x");
        require(publicSignals[3] == aggregateCiphertext.c1y, "Wrong aggregate c1y");
        require(publicSignals[4] == shareX, "Wrong share x");
        require(publicSignals[5] == shareY, "Wrong share y");
    }

    function _resetAggregateCiphertexts() internal {
        for (uint8 i = 0; i < CANDIDATE_COUNT; i++) {
            aggregateCiphertexts[i] = Ciphertext({
                c1x: 0,
                c1y: 1,
                c2x: 0,
                c2y: 1
            });
        }
    }

    function _accumulateCiphertexts(Ciphertext[2] calldata ciphertexts) internal {
        for (uint8 i = 0; i < CANDIDATE_COUNT; i++) {
            Ciphertext storage aggregateCiphertext = aggregateCiphertexts[i];
            (aggregateCiphertext.c1x, aggregateCiphertext.c1y) = _babyAdd(
                aggregateCiphertext.c1x,
                aggregateCiphertext.c1y,
                ciphertexts[i].c1x,
                ciphertexts[i].c1y
            );
            (aggregateCiphertext.c2x, aggregateCiphertext.c2y) = _babyAdd(
                aggregateCiphertext.c2x,
                aggregateCiphertext.c2y,
                ciphertexts[i].c2x,
                ciphertexts[i].c2y
            );
        }
    }

    function _babyAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2)
        internal
        view
        returns (uint256 xout, uint256 yout)
    {
        uint256 beta = mulmod(x1, y2, BABYJUB_FIELD);
        uint256 gamma = mulmod(y1, x2, BABYJUB_FIELD);
        uint256 ax1 = mulmod(BABYJUB_A, x1, BABYJUB_FIELD);
        uint256 deltaLeft = _modSub(y1, ax1);
        uint256 deltaRight = addmod(x2, y2, BABYJUB_FIELD);
        uint256 delta = mulmod(deltaLeft, deltaRight, BABYJUB_FIELD);
        uint256 tau = mulmod(beta, gamma, BABYJUB_FIELD);

        uint256 denominatorX = addmod(1, mulmod(BABYJUB_D, tau, BABYJUB_FIELD), BABYJUB_FIELD);
        uint256 denominatorY = _modSub(1, mulmod(BABYJUB_D, tau, BABYJUB_FIELD));
        require(denominatorX != 0 && denominatorY != 0, "Degenerate BabyJub add");

        xout = mulmod(addmod(beta, gamma, BABYJUB_FIELD), _modInverse(denominatorX), BABYJUB_FIELD);
        yout = mulmod(
            _modSub(addmod(delta, mulmod(BABYJUB_A, beta, BABYJUB_FIELD), BABYJUB_FIELD), gamma),
            _modInverse(denominatorY),
            BABYJUB_FIELD
        );
    }

    function _modSub(uint256 left, uint256 right) internal pure returns (uint256) {
        return addmod(left, BABYJUB_FIELD - (right % BABYJUB_FIELD), BABYJUB_FIELD);
    }

    function _modInverse(uint256 value) internal view returns (uint256) {
        require(value != 0, "Inverse of zero");
        return _modExp(value, BABYJUB_FIELD - 2);
    }

    function _modExp(uint256 base, uint256 exponent) internal view returns (uint256 result) {
        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), base, exponent, BABYJUB_FIELD);
        bytes memory output = new bytes(32);
        bool success;

        assembly {
            success := staticcall(gas(), 0x05, add(input, 32), mload(input), add(output, 32), 32)
        }

        require(success, "Modexp failed");
        result = abi.decode(output, (uint256));
    }
}
