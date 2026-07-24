// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.11;

contract CompatibilityProbe {
    bytes32 public lastDigest;

    event Anchored(bytes32 indexed digest);

    function anchor(bytes32 digest) external {
        lastDigest = digest;
        emit Anchored(digest);
    }
}
