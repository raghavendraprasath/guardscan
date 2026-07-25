// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Intentionally vulnerable vault for GuardScan demo fixtures.
/// @dev DO NOT deploy on mainnet. Used only as a scanner true-positive target.
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @dev Missing access control: anyone can take ownership.
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    /// @dev tx.origin auth anti-pattern.
    function privilegedWithdraw() external {
        require(tx.origin == owner, "not owner");
        uint256 amount = address(this).balance;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "send failed");
    }

    /// @dev Classic reentrancy: external call before state update.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}
