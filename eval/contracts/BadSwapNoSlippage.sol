// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Labeled eval case: swap without minOut / amountOutMin.
contract BadSwapNoSlippage {
    IERC20Like public token0;
    IERC20Like public token1;
    uint256 public reserve0;
    uint256 public reserve1;

    function swap(address tokenIn, uint256 amountIn) external returns (uint256 amountOut) {
        bool isToken0 = tokenIn == address(token0);
        amountOut = isToken0
            ? (amountIn * reserve1) / (reserve0 + amountIn)
            : (amountIn * reserve0) / (reserve1 + amountIn);
        if (isToken0) {
            token0.transferFrom(msg.sender, address(this), amountIn);
            token1.transfer(msg.sender, amountOut);
        } else {
            token1.transferFrom(msg.sender, address(this), amountIn);
            token0.transfer(msg.sender, amountOut);
        }
    }
}
