// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.11;

import "../../contracts/fisco-bcos/TrustDBAnchorV1.sol";

/// @dev The compatibility probe executes the production anchor contract on
/// both standard and Guomi Air networks while preserving the compact event
/// expected by the compatibility evidence collector.
contract CompatibilityProbe is TrustDBAnchorV1 {
    bytes32 private constant STREAM_ID =
        0x917e5b56d8566402571e8152e753aaa8f07f37c70f019ad3d97841a6a1b040d5;
    bytes32 private constant ROOT_HASH =
        0x994305566f2628e97309e68b846c4648d46fe6278091603a541659479053fd74;

    event Anchored(bytes32 indexed digest);

    constructor() TrustDBAnchorV1(msg.sender, _singleton(msg.sender)) {}

    function anchor(bytes32 digest) external {
        publish(digest, STREAM_ID, 1, ROOT_HASH, digest, PAYLOAD_VERSION);
        emit Anchored(digest);
    }

    function _singleton(address publisher) private pure returns (address[] memory result) {
        result = new address[](1);
        result[0] = publisher;
    }
}
