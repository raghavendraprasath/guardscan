// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Labeled eval case: sensitive setter with no authorization.
contract BadAccessControl {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
