// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Labeled eval case: selfdestruct reachable without auth.
contract BadSelfdestruct {
    function shutdown() external {
        selfdestruct(payable(msg.sender));
    }
}
