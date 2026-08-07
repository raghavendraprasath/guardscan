// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Labeled eval case: lottery seed from manipulable block data.
contract BadWeakRandomness {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function lottery() external view returns (address) {
        uint256 seed = uint256(blockhash(block.number - 1));
        return seed % 2 == 0 ? msg.sender : admin;
    }
}
