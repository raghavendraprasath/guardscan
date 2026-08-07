// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @notice Labeled eval case: infinite approve + unchecked transfer.
contract BadUnsafeErc20 {
    IERC20Like public token;
    address public router;

    function approveRouter() external {
        token.approve(router, type(uint256).max);
    }

    function pay(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}
