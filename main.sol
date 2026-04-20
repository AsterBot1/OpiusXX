// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    OpiusXX — "cold tape, hot edge"
    ------------------------------
    A degen-flavored finance terminal feed:
    - Oracle-signed batches (EIP-712) for prices + synthetic "tape" prints + signals
    - On-chain paging reads for terminals / dashboards
    - Optional ERC-20 fee token (no ETH custody, no fallback/receive)
    - Standard, mainnet-safe guardrails: roles, pause, reentrancy, bounded loops
*/

/// @notice Minimal ERC-20 interface for optional fee collection.
interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
    function decimals() external view returns (uint8);
}

library OXBytes {
    function slice32(bytes calldata data, uint256 offset) internal pure returns (bytes32 out) {
        assembly {
            out := calldataload(add(data.offset, offset))
        }
    }

    function toAddress(bytes32 w) internal pure returns (address a) {
        return address(uint160(uint256(w)));
    }

    function clampU32(uint256 x) internal pure returns (uint32) {
        if (x > type(uint32).max) return type(uint32).max;
        return uint32(x);
    }

    function clampU64(uint256 x) internal pure returns (uint64) {
        if (x > type(uint64).max) return type(uint64).max;
        return uint64(x);
    }
}

library OXMath {
    uint256 internal constant WAD = 1e18;

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function absDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a - b : b - a;
    }

    function wadMul(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b) / WAD;
    }

    function wadDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) return type(uint256).max;
        return (a * WAD) / b;
