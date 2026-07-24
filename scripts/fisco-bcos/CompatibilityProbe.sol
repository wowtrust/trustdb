// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.11;

import "../../contracts/fisco-bcos/TrustDBAnchorV1.sol";

/// @dev The compatibility probe only supplies deterministic constructor
/// arguments. Its runtime surface is the inherited production contract: the
/// harness calls publish(), validates AnchorPublished, and reads getAnchor().
contract CompatibilityProbe is TrustDBAnchorV1 {
    constructor() TrustDBAnchorV1(msg.sender, _singleton(msg.sender)) {}

    function _singleton(address publisher) private pure returns (address[] memory result) {
        result = new address[](1);
        result[0] = publisher;
    }
}
