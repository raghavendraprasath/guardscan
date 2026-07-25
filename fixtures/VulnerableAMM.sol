// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice Intentionally vulnerable AMM-style swap for GuardScan demo fixtures.
/// @dev DO NOT deploy on mainnet. Used only as a scanner true-positive target.
contract VulnerableAMM {
    IERC20Like public token0;
    IERC20Like public token1;
    uint256 public reserve0;
    uint256 public reserve1;
    address public owner;

    constructor(address t0, address t1) {
        token0 = IERC20Like(t0);
        token1 = IERC20Like(t1);
        owner = msg.sender;
    }

    /// @dev Missing access control on a sensitive admin function.
    function setReserves(uint256 r0, uint256 r1) external {
        reserve0 = r0;
        reserve1 = r1;
    }

    /// @dev Swap without slippage protection (no minOut / amountOutMin).
    function swap(address tokenIn, uint256 amountIn) external returns (uint256 amountOut) {
        require(amountIn > 0, "zero in");
        bool isToken0 = tokenIn == address(token0);
        require(isToken0 || tokenIn == address(token1), "bad token");

        // Simplified constant-product style quote (toy math, not production).
        if (isToken0) {
            amountOut = (amountIn * reserve1) / (reserve0 + amountIn);
            token0.transferFrom(msg.sender, address(this), amountIn);
            // Unsafe: ignore ERC-20 return value.
            token1.transfer(msg.sender, amountOut);
            reserve0 += amountIn;
            reserve1 -= amountOut;
        } else {
            amountOut = (amountIn * reserve0) / (reserve1 + amountIn);
            token1.transferFrom(msg.sender, address(this), amountIn);
            token0.transfer(msg.sender, amountOut);
            reserve1 += amountIn;
            reserve0 -= amountOut;
        }
    }

    /// @dev Infinite approval anti-pattern.
    function approveRouter(address router) external {
        token0.approve(router, type(uint256).max);
        token1.approve(router, type(uint256).max);
    }
}
