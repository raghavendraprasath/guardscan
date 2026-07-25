// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Safer-ish AMM-style swap snippet for GuardScan contrast fixture.
/// @dev Still educational — not production-ready DeFi.
contract SaferAMM {
    IERC20Like public token0;
    IERC20Like public token1;
    uint256 public reserve0;
    uint256 public reserve1;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address t0, address t1) {
        token0 = IERC20Like(t0);
        token1 = IERC20Like(t1);
        owner = msg.sender;
    }

    function setReserves(uint256 r0, uint256 r1) external onlyOwner {
        reserve0 = r0;
        reserve1 = r1;
    }

    /// @notice Swap with minOut slippage guard and checks-effects-interactions style updates.
    function swap(address tokenIn, uint256 amountIn, uint256 minOut) external returns (uint256 amountOut) {
        require(amountIn > 0, "zero in");
        bool isToken0 = tokenIn == address(token0);
        require(isToken0 || tokenIn == address(token1), "bad token");

        if (isToken0) {
            amountOut = (amountIn * reserve1) / (reserve0 + amountIn);
            require(amountOut >= minOut, "slippage");
            reserve0 += amountIn;
            reserve1 -= amountOut;
            require(token0.transferFrom(msg.sender, address(this), amountIn), "transferFrom failed");
            require(token1.transfer(msg.sender, amountOut), "transfer failed");
        } else {
            amountOut = (amountIn * reserve0) / (reserve1 + amountIn);
            require(amountOut >= minOut, "slippage");
            reserve1 += amountIn;
            reserve0 -= amountOut;
            require(token1.transferFrom(msg.sender, address(this), amountIn), "transferFrom failed");
            require(token0.transfer(msg.sender, amountOut), "transfer failed");
        }
    }
}
