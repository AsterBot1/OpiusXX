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
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }
}

library OXERC20 {
    error OXERC20__TransferFailed();
    error OXERC20__TransferFromFailed();

    function safeTransfer(IERC20Like token, address to, uint256 amount) internal {
        (bool ok, bytes memory ret) = address(token).call(abi.encodeWithSelector(token.transfer.selector, to, amount));
        if (!ok) revert OXERC20__TransferFailed();
        if (ret.length > 0 && !abi.decode(ret, (bool))) revert OXERC20__TransferFailed();
    }

    function safeTransferFrom(IERC20Like token, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory ret) =
            address(token).call(abi.encodeWithSelector(token.transferFrom.selector, from, to, amount));
        if (!ok) revert OXERC20__TransferFromFailed();
        if (ret.length > 0 && !abi.decode(ret, (bool))) revert OXERC20__TransferFromFailed();
    }
}

abstract contract OXReentrancy {
    error OXReentrancy__Reentered();

    uint256 private _oxGuard = 1;

    modifier nonReentrant() {
        if (_oxGuard != 1) revert OXReentrancy__Reentered();
        _oxGuard = 2;
        _;
        _oxGuard = 1;
    }
}

abstract contract OXPausable {
    error OXPausable__Paused();

    bool public paused;

    modifier whenLive() {
        if (paused) revert OXPausable__Paused();
        _;
    }

    function _setPaused(bool v) internal {
        paused = v;
    }
}

abstract contract OXRoles {
    error OXRoles__Denied(bytes32 role, address who);
    error OXRoles__ZeroAddress();
    error OXRoles__RoleLocked(bytes32 role);

    event OX_RoleGranted(bytes32 indexed role, address indexed account, address indexed caller);
    event OX_RoleRevoked(bytes32 indexed role, address indexed account, address indexed caller);
    event OX_RoleLocked(bytes32 indexed role, address indexed locker);

    mapping(bytes32 => mapping(address => bool)) internal _hasRole;
    mapping(bytes32 => bool) internal _roleLocked;

    modifier onlyRole(bytes32 role) {
        if (!_hasRole[role][msg.sender]) revert OXRoles__Denied(role, msg.sender);
        _;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _hasRole[role][account];
    }

    function roleLocked(bytes32 role) public view returns (bool) {
        return _roleLocked[role];
    }

    function _grantRole(bytes32 role, address account) internal {
        if (account == address(0)) revert OXRoles__ZeroAddress();
        if (!_hasRole[role][account]) {
            _hasRole[role][account] = true;
            emit OX_RoleGranted(role, account, msg.sender);
        }
    }

    function _revokeRole(bytes32 role, address account) internal {
        if (_hasRole[role][account]) {
            _hasRole[role][account] = false;
            emit OX_RoleRevoked(role, account, msg.sender);
        }
    }

    function _lockRole(bytes32 role) internal {
        if (_roleLocked[role]) revert OXRoles__RoleLocked(role);
        _roleLocked[role] = true;
        emit OX_RoleLocked(role, msg.sender);
    }
}

library OXRing {
    error OXRing__BadIndex();
    error OXRing__ZeroCapacity();

    struct U64Ring {
        uint64 head;
        uint64 count;
        uint64 cap;
        mapping(uint256 => uint64) at;
    }

    function init(U64Ring storage r, uint64 capacity) internal {
        if (capacity == 0) revert OXRing__ZeroCapacity();
        r.cap = capacity;
    }

    function push(U64Ring storage r, uint64 v) internal {
        uint64 cap = r.cap;
        if (cap == 0) revert OXRing__ZeroCapacity();
        uint64 idx = r.head;
        r.at[uint256(idx)] = v;
        unchecked {
            r.head = uint64((uint256(idx) + 1) % uint256(cap));
        }
        if (r.count < cap) r.count += 1;
    }

    function size(U64Ring storage r) internal view returns (uint64) {
        return r.count;
    }

    function capacity(U64Ring storage r) internal view returns (uint64) {
        return r.cap;
    }

    /// @notice Get element by age where 0 = newest.
    function getNewestFirst(U64Ring storage r, uint64 age) internal view returns (uint64) {
        uint64 n = r.count;
        if (age >= n) revert OXRing__BadIndex();
        uint64 cap = r.cap;
        uint64 head = r.head;
        unchecked {
            uint64 newestIndex = head == 0 ? (cap - 1) : (head - 1);
            uint64 idx = uint64((uint256(newestIndex) + uint256(cap) - uint256(age)) % uint256(cap));
            return r.at[uint256(idx)];
        }
    }
}

contract OpiusXX is OXRoles, OXPausable, OXReentrancy {
    using OXERC20 for IERC20Like;
    using OXMath for uint256;
    using OXRing for OXRing.U64Ring;

    // ============
    // Errors (distinct per-contract)
    // ============
    error OPX__BadConfig();
    error OPX__BadCursor();
    error OPX__OutOfRange();
    error OPX__UnknownInstrument(uint32 instrumentId);
    error OPX__SymbolRejected();
    error OPX__StaleBatch(uint64 batchTs);
    error OPX__NonceMismatch();
    error OPX__SignatureRejected();
    error OPX__FeeTokenUnset();
    error OPX__FeeTooHigh();
    error OPX__FeePaymentFailed();
    error OPX__RoleIsLocked(bytes32 role);

    // ============
    // Events (distinct per-contract)
    // ============
    event OPX_Paused(bool paused);
    event OPX_FeePolicySet(address indexed token, uint256 indexed feePerBatch, address indexed sink);
    event OPX_InstrumentListed(uint32 indexed instrumentId, bytes16 indexed symbol, uint8 decimals, uint8 kind);
    event OPX_InstrumentTuned(uint32 indexed instrumentId, uint32 maxTapeDepth, uint32 maxSignalDepth);
    event OPX_BatchAccepted(uint64 indexed batchTs, uint64 indexed batchSeq, uint32 indexed instrumentCount);
    event OPX_TapePrint(uint32 indexed instrumentId, uint64 indexed ts, int64 px, int64 qty, uint8 side);
    event OPX_SignalPushed(uint32 indexed instrumentId, uint64 indexed ts, int64 score, bytes16 tag);
    event OPX_WatchPinned(address indexed who, uint32 indexed instrumentId, uint8 slot);
    event OPX_WatchCleared(address indexed who, uint8 slot);
    event OPX_RoleLatch(bytes32 indexed role, address indexed caller);

    // ============
    // Roles (mainstream keccak strings)
    // ============
    bytes32 public constant ROLE_GOVERNOR = keccak256("OpiusXX.ROLE_GOVERNOR");
    bytes32 public constant ROLE_ORACLE = keccak256("OpiusXX.ROLE_ORACLE");
    bytes32 public constant ROLE_GUARDIAN = keccak256("OpiusXX.ROLE_GUARDIAN");
    bytes32 public constant ROLE_RISK = keccak256("OpiusXX.ROLE_RISK");
    bytes32 public constant ROLE_FEESINK = keccak256("OpiusXX.ROLE_FEESINK");

    // ============
    // Immutable anchors (workspace-unique, no special power)
    // ============
    address public immutable ANCHOR_0;
    address public immutable ANCHOR_1;
    address public immutable ANCHOR_2;
    address public immutable ANCHOR_3;

    // ============
    // Fee policy
    // ============
    IERC20Like public feeToken;
    uint256 public feePerBatch;
    address public feeSink;
    uint256 public constant MAX_FEE_PER_BATCH = 9_900_000 * 1e6;

    // ============
    // Terminal identity constants (fresh identifiers for this output)
    // ============
    bytes32 private constant _OPX_SEED_A =
        hex"2ecd981c4f3d03d5999eb1a1000cf00bd84421f4153a107c74a8af63f2293ec1";
    bytes32 private constant _OPX_SEED_B =
        hex"f804c492e7c7ce7b2bd2dcfdcc0cecae4bd5d2bbeab9816cf9ae04ec6c7e7334";
    bytes32 private constant _OPX_SEED_C =
        hex"a0ed39ecab829a7fbdd1c5d23986748bed4a5e11c24410a0d1a5dbf02f927c52";
    bytes32 private constant _OPX_SEED_D =
        hex"2303c267408e2f31b29433eaf004db5c9c04e730914fd172de7061cf6633e6ca";
    bytes32 private constant _OPX_SEED_E =
        hex"1fe620bf1c73a00e9f61bfb7be5d6ac055bc9c20af1e74a9e5188b1231fc0006";

    // ============
    // EIP-712 for oracle batches
    // ============
    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 public immutable DEPLOY_CHAIN_ID;
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private constant _BATCH_TYPEHASH = keccak256(
        "OpiusXXBatch(uint64 batchTs,uint64 batchSeq,uint32 instrumentCount,bytes32 manifestHash,bytes32 dataHash,uint256 fee,uint256 nonce,address payer)"
    );

    mapping(address => uint256) public oracleNonces;

    // ============
    // Data model
    // ============
    enum InstrumentKind {
        Spot,
        Perp,
        Index,
        Rate,
        Synthetic
    }

    struct Instrument {
        bytes16 symbol;
        uint8 decimals;
        uint8 kind;
        uint32 maxTapeDepth;
        uint32 maxSignalDepth;
        bool active;
    }

    struct Quote {
