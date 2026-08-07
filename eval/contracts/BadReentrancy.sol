// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Labeled eval case: classic reentrancy (call before state zero).
contract BadReentrancy {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}
