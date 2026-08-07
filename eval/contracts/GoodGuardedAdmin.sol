// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Labeled eval case: sensitive actions behind onlyAdmin / msg.sender checks.
/// Expected: zero findings (true-negative control).
contract GoodGuardedAdmin {
    address public admin;
    uint256 public fee;
    uint256 public rate;

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function setFee(uint256 f) external onlyAdmin {
        fee = f;
    }

    function setRate(uint256 r) external {
        require(msg.sender == admin, "not admin");
        rate = r;
    }

    function destroy() external onlyAdmin {
        selfdestruct(payable(admin));
    }

    function deadline() external view returns (bool) {
        return block.timestamp > 100;
    }
}
