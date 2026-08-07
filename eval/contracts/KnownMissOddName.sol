// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Intentionally NOT covered by GuardScan detectors.
/// A real access-control bug under a name that matches no sensitive prefix
/// (`configureParameters` ≠ set/update/mint/...). Used to measure a known false negative.
contract KnownMissOddName {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function configureParameters(address newOwner) external {
        owner = newOwner;
    }
}
