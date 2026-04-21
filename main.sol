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
        uint64 ts;
        int64 midPx;
        int64 spreadBps;
        int64 fundingBps;
        uint64 openInterest;
    }

    struct Tape {
        uint64 ts;
        int64 px;
        int64 qty;
        uint8 side; // 0=unknown,1=buy,2=sell
    }

    struct Signal {
        uint64 ts;
        int64 score;
        bytes16 tag;
    }

    uint32 public instrumentCount;
    mapping(uint32 => Instrument) public instruments;

    mapping(uint32 => Quote) public lastQuote;
    mapping(uint32 => OXRing.U64Ring) private _tapeIx;
    mapping(uint32 => mapping(uint256 => Tape)) private _tape;
    mapping(uint32 => OXRing.U64Ring) private _sigIx;
    mapping(uint32 => mapping(uint256 => Signal)) private _sig;

    uint64 public lastBatchTs;
    uint64 public lastBatchSeq;
    bytes32 public lastManifestHash;
    bytes32 public lastDataHash;

    // ============
    // Watchlist (8 slots) for terminals
    // ============
    uint8 public constant WATCH_SLOTS = 8;
    mapping(address => uint32[WATCH_SLOTS]) private _watch;
    mapping(address => uint8[WATCH_SLOTS]) private _watchSet;

    // ============
    // User scribbles (terminal notes) — bounded ring per user
    // ============
    struct Scribble {
        uint64 ts;
        bytes16 topic;
        bytes32 payloadHash;
        int64 mood; // arbitrary signed score (e.g. -100..100)
    }

    uint32 public constant SCRIBBLE_CAP_MIN = 16;
    uint32 public constant SCRIBBLE_CAP_MAX = 512;
    uint32 public scribbleCap;
    mapping(address => OXRing.U64Ring) private _scribIx;
    mapping(address => mapping(uint256 => Scribble)) private _scrib;
    event OPX_Scribble(address indexed who, uint64 indexed ts, bytes16 indexed topic, bytes32 payloadHash, int64 mood);

    // ============
    // Defaults (constructor injection w/ zero-arg deploy)
    // ============
    address private constant _DEF_GOV = 0x3E0CE056e90aFB0B23AB998435F9985379C6551a;
    address private constant _DEF_ORACLE = 0x10F5D6C227D7E5b749Bbf57F14f59643d8AD6544;
    address private constant _DEF_GUARD = 0x6A1656172774edAE253cE1aA0486607D1d52612B;
    address private constant _DEF_RISK = 0x81ff36F2D1fED81155978176eFBc3Dd869daA506;
    address private constant _DEF_SINK = 0xfdc679937f21365Ab1c64d7fb8d9DB4974748b55;

    address private constant _DEF_ANCH0 = 0x884922d2D7c7F841a740f5109491c93aF587f225;
    address private constant _DEF_ANCH1 = 0xf7e1A45c4Ec3693d4D8685bBE51494f24859d2F2;
    address private constant _DEF_ANCH2 = 0x914FAC317e024038Bd7769537d051F12D6bE799F;
    address private constant _DEF_ANCH3 = 0x6a8b44d6881F1F428a1f0E5513db9B247AFA9F77;

    address private constant _DEF_FEE_TOKEN = 0xa735860Cc110c7B23079f87755B4FdD924D361FA;

    // ============
    // Constructor
    // ============
    constructor(address governor, address oracle, address guardian, address risk, address sink, address feeToken_) {
        address gov = governor == address(0) ? _DEF_GOV : governor;
        address ora = oracle == address(0) ? _DEF_ORACLE : oracle;
        address grd = guardian == address(0) ? _DEF_GUARD : guardian;
        address rsk = risk == address(0) ? _DEF_RISK : risk;
        address snk = sink == address(0) ? _DEF_SINK : sink;

        _grantRole(ROLE_GOVERNOR, gov);
        _grantRole(ROLE_ORACLE, ora);
        _grantRole(ROLE_GUARDIAN, grd);
        _grantRole(ROLE_RISK, rsk);
        _grantRole(ROLE_FEESINK, snk);

        ANCHOR_0 = _DEF_ANCH0;
        ANCHOR_1 = _DEF_ANCH1;
        ANCHOR_2 = _DEF_ANCH2;
        ANCHOR_3 = _DEF_ANCH3;

        IERC20Like ft = IERC20Like(feeToken_ == address(0) ? _DEF_FEE_TOKEN : feeToken_);
        feeToken = ft;
        feeSink = snk;
        feePerBatch = 0;

        uint32 cap = uint32(48 + (uint256(keccak256(abi.encode(_OPX_SEED_E, block.prevrandao, address(this)))) % 144));
        scribbleCap = cap;

        DEPLOY_CHAIN_ID = block.chainid;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("OpiusXX")),
                keccak256(bytes("0.9.7")),
                block.chainid,
                address(this)
            )
        );
    }

    // ============
    // Governance
    // ============
    function setPaused(bool v) external onlyRole(ROLE_GUARDIAN) {
        _setPaused(v);
        emit OPX_Paused(v);
    }

    function setFeePolicy(IERC20Like token, uint256 perBatch, address sink) external onlyRole(ROLE_GOVERNOR) {
        if (address(token) == address(0)) revert OPX__BadConfig();
        if (sink == address(0)) revert OPX__BadConfig();
        if (perBatch > MAX_FEE_PER_BATCH) revert OPX__FeeTooHigh();
        feeToken = token;
        feePerBatch = perBatch;
        feeSink = sink;
        emit OPX_FeePolicySet(address(token), perBatch, sink);
    }

    function grant(bytes32 role, address account) external onlyRole(ROLE_GOVERNOR) {
        if (_roleLocked[role]) revert OPX__RoleIsLocked(role);
        _grantRole(role, account);
    }

    function revoke(bytes32 role, address account) external onlyRole(ROLE_GOVERNOR) {
        if (_roleLocked[role]) revert OPX__RoleIsLocked(role);
        _revokeRole(role, account);
    }

    function lockRole(bytes32 role) external onlyRole(ROLE_GOVERNOR) {
        _lockRole(role);
        emit OPX_RoleLatch(role, msg.sender);
    }

    function setScribbleCap(uint32 cap) external onlyRole(ROLE_GOVERNOR) {
        if (cap < SCRIBBLE_CAP_MIN || cap > SCRIBBLE_CAP_MAX) revert OPX__BadConfig();
        scribbleCap = cap;
    }

    // ============
    // Instrument catalog
    // ============
    function listInstrument(bytes16 symbol, uint8 decimals, InstrumentKind kind) external onlyRole(ROLE_RISK) returns (uint32 id) {
        if (symbol == bytes16(0)) revert OPX__SymbolRejected();
        if (decimals > 24) revert OPX__BadConfig();

        id = instrumentCount + 1;
        instrumentCount = id;

        uint32 tapeDepth = uint32(64 + (uint256(keccak256(abi.encode(_OPX_SEED_A, id, symbol))) % 128));
        uint32 sigDepth = uint32(32 + (uint256(keccak256(abi.encode(_OPX_SEED_B, symbol, id))) % 96));

        instruments[id] = Instrument({
            symbol: symbol,
            decimals: decimals,
            kind: uint8(kind),
            maxTapeDepth: tapeDepth,
            maxSignalDepth: sigDepth,
            active: true
        });

        _tapeIx[id].init(uint64(tapeDepth));
        _sigIx[id].init(uint64(sigDepth));

        emit OPX_InstrumentListed(id, symbol, decimals, uint8(kind));
        emit OPX_InstrumentTuned(id, tapeDepth, sigDepth);
    }

    function setInstrumentActive(uint32 instrumentId, bool active) external onlyRole(ROLE_RISK) {
        Instrument storage ins = instruments[instrumentId];
        if (ins.symbol == bytes16(0)) revert OPX__UnknownInstrument(instrumentId);
        ins.active = active;
    }

    function tuneDepth(uint32 instrumentId, uint32 tapeDepth, uint32 signalDepth) external onlyRole(ROLE_RISK) {
        Instrument storage ins = instruments[instrumentId];
        if (ins.symbol == bytes16(0)) revert OPX__UnknownInstrument(instrumentId);
        if (tapeDepth < 16 || tapeDepth > 1024) revert OPX__BadConfig();
        if (signalDepth < 8 || signalDepth > 1024) revert OPX__BadConfig();

        ins.maxTapeDepth = tapeDepth;
        ins.maxSignalDepth = signalDepth;
        _tapeIx[instrumentId].init(uint64(tapeDepth));
        _sigIx[instrumentId].init(uint64(signalDepth));
        emit OPX_InstrumentTuned(instrumentId, tapeDepth, signalDepth);
    }

    // ============
    // Watchlist
    // ============
    function pinWatch(uint8 slot, uint32 instrumentId) external {
        if (slot >= WATCH_SLOTS) revert OPX__OutOfRange();
        if (instrumentId != 0) {
            Instrument storage ins = instruments[instrumentId];
            if (ins.symbol == bytes16(0) || !ins.active) revert OPX__UnknownInstrument(instrumentId);
            _watch[msg.sender][slot] = instrumentId;
            _watchSet[msg.sender][slot] = 1;
            emit OPX_WatchPinned(msg.sender, instrumentId, slot);
        } else {
            _watch[msg.sender][slot] = 0;
            _watchSet[msg.sender][slot] = 0;
            emit OPX_WatchCleared(msg.sender, slot);
        }
    }

    function getWatch(address who) external view returns (uint32[WATCH_SLOTS] memory ids, uint8[WATCH_SLOTS] memory isSet) {
        return (_watch[who], _watchSet[who]);
    }

    // ============
    // Scribbles
    // ============
    function postScribble(bytes16 topic, bytes32 payloadHash, int64 mood) external whenLive {
        if (topic == bytes16(0) || payloadHash == bytes32(0)) revert OPX__BadConfig();
        if (mood < -10_000 || mood > 10_000) revert OPX__OutOfRange();

        OXRing.U64Ring storage r = _scribIx[msg.sender];
        if (r.capacity() == 0) r.init(uint64(scribbleCap));

        uint64 idx = r.size();
        r.push(uint64(idx));
        uint64 ts = uint64(block.timestamp);
        _scrib[msg.sender][uint256(idx)] = Scribble({ts: ts, topic: topic, payloadHash: payloadHash, mood: mood});
        emit OPX_Scribble(msg.sender, ts, topic, payloadHash, mood);
    }

    function getScribblesNewestFirst(address who, uint64 offsetAge, uint64 limit)
        external
        view
        returns (Scribble[] memory out)
    {
        OXRing.U64Ring storage r = _scribIx[who];
        uint64 n = r.size();
        if (offsetAge > n) revert OPX__OutOfRange();
        uint64 remaining = n - offsetAge;
        uint64 take = limit;
        if (take > remaining) take = remaining;

        out = new Scribble[](take);
        for (uint64 i = 0; i < take; i++) {
            uint64 age = offsetAge + i;
            uint64 idx = r.getNewestFirst(age);
            out[i] = _scrib[who][uint256(idx)];
        }
    }

    // ============
    // Oracle batch ingestion
    // ============
    struct BatchHeader {
        uint64 batchTs;
        uint64 batchSeq;
        uint32 instrumentCountInBatch;
        bytes32 manifestHash;
        bytes32 dataHash;
        uint256 fee;
        uint256 nonce;
        address payer;
    }

    struct BatchSig {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// @notice Accept an oracle-signed batch.
    /// @dev `packed` encodes rows; this avoids arrays-of-structs overhead.
    /// Layout:
    /// - Quotes: instrumentCountInBatch rows of 56 bytes:
    ///   [u32 id][u64 ts][i64 mid][i32 spreadBps][i32 fundingBps][u64 oi]
    /// - Tape: variable rows of 32 bytes:
    ///   [u32 id][u64 ts][i64 px][i32 qty32][u8 side][u8 pad][u16 pad]
    /// - Signals: variable rows of 32 bytes:
    ///   [u32 id][u64 ts][i64 score][bytes16 tag]
    /// With section cursors in `manifestHash` high bits to prevent ambiguous parsing.
    function ingest(
        BatchHeader calldata h,
        BatchSig calldata sig,
        bytes calldata packed
    ) external whenLive nonReentrant {
        if (!hasRole(ROLE_ORACLE, msg.sender) && !hasRole(ROLE_ORACLE, _recover(h, sig))) {
            revert OPX__SignatureRejected();
        }

        if (h.batchTs < lastBatchTs) revert OPX__StaleBatch(h.batchTs);
        if (h.batchTs == lastBatchTs && h.batchSeq <= lastBatchSeq) revert OPX__StaleBatch(h.batchTs);

        address signer = _recover(h, sig);
        if (!hasRole(ROLE_ORACLE, signer)) revert OPX__SignatureRejected();

        if (oracleNonces[signer] != h.nonce) revert OPX__NonceMismatch();
        oracleNonces[signer] = h.nonce + 1;

        if (h.instrumentCountInBatch == 0 || h.instrumentCountInBatch > instrumentCount) revert OPX__BadConfig();

        bytes32 computed = keccak256(packed);
        if (computed != h.dataHash) revert OPX__SignatureRejected();

        _maybeCollectFee(h);

        (uint32 quoteRows, uint32 tapeRows, uint32 sigRows) = _unpackManifest(h.manifestHash);
        if (quoteRows != h.instrumentCountInBatch) revert OPX__BadConfig();

        uint256 cursor = 0;
        cursor = _applyQuotes(quoteRows, cursor, packed);
        cursor = _applyTape(tapeRows, cursor, packed);
        cursor = _applySignals(sigRows, cursor, packed);
        if (cursor != packed.length) revert OPX__BadCursor();

        lastBatchTs = h.batchTs;
