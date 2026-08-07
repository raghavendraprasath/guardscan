// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Labeled eval case: unrestricted delegatecall to a caller-chosen target.
contract BadDelegatecall {
    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "call failed");
    }
}
