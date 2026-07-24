// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.11;

/// @title TrustDBAnchorV1
/// @notice Immutable publication boundary for TrustDB Signed Tree Head anchors.
/// @dev The contract deliberately does not hash or reinterpret TrustDB roots.
///      Callers and offline verifiers recompute the versioned AnchorID defined
///      by ADR-0013 before trusting an emitted event.
contract TrustDBAnchorV1 {
    uint16 public constant PAYLOAD_VERSION = 1;

    struct AnchorRecord {
        bytes32 streamID;
        uint64 treeSize;
        bytes32 rootHash;
        bytes32 signedSTHDigest;
        address publisher;
        uint16 payloadVersion;
        bool exists;
    }

    struct StreamHead {
        uint64 treeSize;
        bytes32 rootHash;
        bool exists;
    }

    address public immutable administrator;
    uint256 public publisherCount;

    mapping(address => bool) public publishers;
    mapping(bytes32 => AnchorRecord) private anchors;
    mapping(bytes32 => StreamHead) private streamHeads;

    error AdministratorRequired(address caller);
    error PublisherRequired(address caller);
    error ZeroAdministrator();
    error ZeroPublisher();
    error EmptyPublisherSet();
    error LastPublisher();
    error DuplicateInitialPublisher(address publisher);
    error InvalidPayloadVersion(uint16 supplied);
    error ZeroAnchorID();
    error ZeroStreamID();
    error ZeroTreeSize();
    error ZeroRootHash();
    error ZeroSignedSTHDigest();
    error AnchorIDConflict(bytes32 anchorID);
    error TreeSizeRegression(bytes32 streamID, uint64 currentTreeSize, uint64 suppliedTreeSize);
    error StreamRootConflict(bytes32 streamID, uint64 treeSize, bytes32 currentRoot, bytes32 suppliedRoot);

    event PublisherAuthorizationChanged(
        address indexed publisher,
        bool authorized,
        address indexed administrator
    );

    event AnchorPublished(
        bytes32 indexed anchorID,
        bytes32 indexed streamID,
        uint64 treeSize,
        bytes32 rootHash,
        bytes32 signedSTHDigest,
        address indexed publisher,
        uint16 payloadVersion
    );

    constructor(address administrator_, address[] memory initialPublishers_) {
        if (administrator_ == address(0)) {
            revert ZeroAdministrator();
        }
        if (initialPublishers_.length == 0) {
            revert EmptyPublisherSet();
        }

        administrator = administrator_;
        for (uint256 i = 0; i < initialPublishers_.length; i++) {
            address publisher = initialPublishers_[i];
            if (publisher == address(0)) {
                revert ZeroPublisher();
            }
            if (publishers[publisher]) {
                revert DuplicateInitialPublisher(publisher);
            }
            publishers[publisher] = true;
            publisherCount++;
            emit PublisherAuthorizationChanged(publisher, true, administrator_);
        }
    }

    modifier onlyAdministrator() {
        if (msg.sender != administrator) {
            revert AdministratorRequired(msg.sender);
        }
        _;
    }

    modifier onlyPublisher() {
        if (!publishers[msg.sender]) {
            revert PublisherRequired(msg.sender);
        }
        _;
    }

    /// @notice Authorize or revoke an anchor publisher.
    /// @dev Repeating the current setting is an idempotent no-op.
    function setPublisher(address publisher, bool authorized) external onlyAdministrator returns (bool changed) {
        if (publisher == address(0)) {
            revert ZeroPublisher();
        }
        if (publishers[publisher] == authorized) {
            return false;
        }

        publishers[publisher] = authorized;
        if (authorized) {
            publisherCount++;
        } else {
            if (publisherCount == 1) {
                revert LastPublisher();
            }
            publisherCount--;
        }
        emit PublisherAuthorizationChanged(publisher, authorized, msg.sender);
        return true;
    }

    /// @notice Publish one exact TrustDB Signed Tree Head anchor.
    /// @return inserted True only when this call created the anchor record.
    /// @dev An exact duplicate succeeds without an event, even after the stream
    ///      has advanced. This makes retry after an unknown outcome safe.
    function publish(
        bytes32 anchorID,
        bytes32 streamID,
        uint64 treeSize,
        bytes32 rootHash,
        bytes32 signedSTHDigest,
        uint16 payloadVersion
    ) public onlyPublisher returns (bool inserted) {
        _validateInput(anchorID, streamID, treeSize, rootHash, signedSTHDigest, payloadVersion);

        AnchorRecord storage existing = anchors[anchorID];
        if (existing.exists) {
            if (
                existing.streamID != streamID ||
                existing.treeSize != treeSize ||
                existing.rootHash != rootHash ||
                existing.signedSTHDigest != signedSTHDigest ||
                existing.payloadVersion != payloadVersion
            ) {
                revert AnchorIDConflict(anchorID);
            }
            return false;
        }

        StreamHead storage head = streamHeads[streamID];
        if (head.exists) {
            if (treeSize < head.treeSize) {
                revert TreeSizeRegression(streamID, head.treeSize, treeSize);
            }
            if (treeSize == head.treeSize && rootHash != head.rootHash) {
                revert StreamRootConflict(streamID, treeSize, head.rootHash, rootHash);
            }
        }

        anchors[anchorID] = AnchorRecord({
            streamID: streamID,
            treeSize: treeSize,
            rootHash: rootHash,
            signedSTHDigest: signedSTHDigest,
            publisher: msg.sender,
            payloadVersion: payloadVersion,
            exists: true
        });

        if (!head.exists || treeSize > head.treeSize) {
            streamHeads[streamID] = StreamHead({
                treeSize: treeSize,
                rootHash: rootHash,
                exists: true
            });
        }

        emit AnchorPublished(
            anchorID,
            streamID,
            treeSize,
            rootHash,
            signedSTHDigest,
            msg.sender,
            payloadVersion
        );
        return true;
    }

    function getAnchor(bytes32 anchorID) external view returns (AnchorRecord memory) {
        return anchors[anchorID];
    }

    function getStreamHead(bytes32 streamID) external view returns (StreamHead memory) {
        return streamHeads[streamID];
    }

    function _validateInput(
        bytes32 anchorID,
        bytes32 streamID,
        uint64 treeSize,
        bytes32 rootHash,
        bytes32 signedSTHDigest,
        uint16 payloadVersion
    ) private pure {
        if (payloadVersion != PAYLOAD_VERSION) {
            revert InvalidPayloadVersion(payloadVersion);
        }
        if (anchorID == bytes32(0)) {
            revert ZeroAnchorID();
        }
        if (streamID == bytes32(0)) {
            revert ZeroStreamID();
        }
        if (treeSize == 0) {
            revert ZeroTreeSize();
        }
        if (rootHash == bytes32(0)) {
            revert ZeroRootHash();
        }
        if (signedSTHDigest == bytes32(0)) {
            revert ZeroSignedSTHDigest();
        }
    }
}
