// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Labeled eval case: tx.origin used for authorization.
contract BadTxOrigin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function privilegedWithdraw() external {
        require(tx.origin == owner, "not owner");
        (bool ok, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok, "send failed");
    }
}
