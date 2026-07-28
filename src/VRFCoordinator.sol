// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BN254} from "./BN254.sol";

/// @notice Consumers implement this to receive randomness.
/// @dev The callback is gas-limited and its failure is isolated. A consumer that
///      reverts here still has its request recorded as fulfilled.
interface IRandomnessConsumer {
    function receiveRandomness(uint256 requestId, bytes32 randomness) external;
}

/// @title VRFCoordinator — single-operator verifiable randomness.
///
/// @notice One operator serves this contract. Because BLS signatures over BN254
///         are deterministic, exactly one valid signature exists for any request,
///         so the operator cannot choose the output. They can decline to publish
///         one; that shows up on chain as an expired request and is counted
///         against them permanently. See `stats`.
///
/// @dev KEY HANDLING — the single most important property of this contract.
///
///      The operator public key is `immutable`, set once in the constructor and
///      fully validated there with `BN254.validateG2`, which includes the
///      [R]P subgroup check. There is no setter and no rotation path, so there is
///      exactly one way a key can enter this contract and that way validates.
///      This is enforced by the compiler rather than by convention: `immutable`
///      state cannot be written outside the constructor.
///
///      Rotation is absent for a security reason, not merely a simplicity one.
///      The output is `keccak256(signature)`, and the signature is a function of
///      the key. An operator able to change the key AFTER seeing a request could
///      try candidate keys until one produced a favourable output — which is
///      exactly the output-grinding this design exists to make impossible.
///      Any future rotation must therefore bind each request to the key epoch
///      that was active when the request was made, and must validate every new
///      key in full. Adding a naive setter would silently destroy the core
///      security property.
contract VRFCoordinator {
    using BN254 for BN254.G2Point;

    // =====================================================================
    //                             parameters
    // =====================================================================

    /// @notice Blocks after which an unfulfilled request may be expired.
    ///
    /// @dev 192 blocks. Chosen against measured Arc behaviour, not rounded.
    ///
    ///      Arc's block time measured 0.5335 s over a 2,000-block sample on
    ///      2026-07-28, so 192 blocks is about 102 seconds.
    ///
    ///      The binding constraint is `BLOCKHASH`, which was measured on Arc to
    ///      expose exactly the last 256 blocks — `blockhash(n-256)` returns a
    ///      value and `blockhash(n-257)` returns zero. Fulfilment needs
    ///      `blockhash(requestBlock + 1)`, so it becomes physically impossible
    ///      once `block.number > requestBlock + 257`.
    ///
    ///      T is set strictly below that hard deadline, leaving 65 blocks (~35 s)
    ///      of slack. That gap is deliberate: it means an expired request is
    ///      always attributable to the operator not answering, and never an
    ///      artefact of the block hash ageing out. The two failure modes must not
    ///      be confusable, because the expiry counter is the accountability
    ///      mechanism the whole trust model rests on.
    ///
    ///      102 seconds is ample for an automated signer — Arc has deterministic
    ///      sub-second finality and a BLS signature takes microseconds. The slack
    ///      absorbs documented Arc-specific failure modes: public RPC rate
    ///      limiting (`-32011 request limit reached`), `txpool is full` under
    ///      load, and the requirement to re-fetch the base fee before every
    ///      submission.
    ///
    ///      T IS ALSO A SECURITY PARAMETER, NOT ONLY A LIVENESS ONE.
    ///
    ///      Anyone holding the operator secret can compute a request's output the
    ///      moment `blockhash(requestBlock + 1)` exists — that is, from
    ///      `requestBlock + 2` — and they hold that knowledge alone until the
    ///      fulfilment lands. T is the ceiling on that exclusive window: at most
    ///      190 blocks, roughly 101 seconds.
    ///
    ///      They still cannot change the output; signatures are deterministic. But
    ///      unpredictability is the product of a randomness service, and a draw one
    ///      party can see in advance is a rigged draw even though the number was
    ///      not chosen. Lowering T, or simply fulfilling promptly, narrows the
    ///      window in which that advantage exists. Raising T widens it.
    ///
    ///      So T trades two things against each other: too low and honest
    ///      fulfilment fails under transient Arc conditions, producing misses that
    ///      are indistinguishable from withholding; too high and a key holder's
    ///      head start grows. 192 sits where the liveness margin is comfortable and
    ///      the exposure stays under two minutes.
    uint256 public constant REQUEST_TIMEOUT_BLOCKS = 192;

    /// @dev Hard deadline imposed by BLOCKHASH, measured at 256 on Arc. Used only
    ///      to assert at construction that the timeout cannot outlive the seed.
    uint256 private constant BLOCKHASH_WINDOW = 256;

    /// @notice Ceiling on the callback gas a requester may ask for.
    /// @dev Stops a request being made unfulfillably expensive. 2,000,000 against
    ///      a 30,000,000 block gas limit leaves the fulfilment itself, which costs
    ///      on the order of 150,000 gas, with an enormous margin.
    uint256 public constant MAX_CALLBACK_GAS = 2_000_000;

    /// @dev Headroom for bookkeeping after the callback returns.
    uint256 private constant CALLBACK_GAS_BUFFER = 40_000;

    // =====================================================================
    //                            operator key
    // =====================================================================

    uint256 public immutable pubkeyX0;
    uint256 public immutable pubkeyX1;
    uint256 public immutable pubkeyY0;
    uint256 public immutable pubkeyY1;

    /// @notice Identifies the operator key this contract is bound to.
    /// @dev Consumers should pin their trust to this value, not to the contract.
    bytes32 public immutable operatorId;

    // =====================================================================
    //                              storage
    // =====================================================================

    enum Status {
        None,
        Pending,
        Fulfilled,
        Expired
    }

    /// @dev Packed into a single slot: 160 + 48 + 32 + 8 = 248 bits.
    struct Request {
        address requester;
        uint48 requestBlock;
        uint32 callbackGasLimit;
        Status status;
    }

    /// @notice Fulfilment record for an operator.
    ///
    /// @dev THESE COUNTERS ARE A CONVENIENCE. THE EVENTS ARE THE PROOF.
    ///
    ///      `expired` under-reports misses, permanently. `expireRequest` is
    ///      permissionless but nobody is paid to call it: the service is free so a
    ///      requester gets no refund for calling it, and the operator is not going
    ///      to mark their own misses. A genuine miss therefore sits in
    ///      `pendingCount()` forever and never reaches `expired`.
    ///
    ///      That also makes `pendingCount()` ambiguous. It conflates requests
    ///      still inside the timeout window, which are not misses, with requests
    ///      past the timeout that nobody bothered to expire, which are. A consumer
    ///      reading that number cannot separate them, and the second group is
    ///      exactly what a withholding operator would want hidden in the first.
    ///
    ///      This is not eventual consistency. The counter can be wrong forever.
    ///
    ///      Compute the real miss rate from events instead. `RandomnessRequested`
    ///      and `RandomnessFulfilled` carry request ids and block numbers, and
    ///      `REQUEST_TIMEOUT_BLOCKS` is a public constant, so a request is missed
    ///      iff it was requested at block b, was never fulfilled, and the chain is
    ///      past b + REQUEST_TIMEOUT_BLOCKS. That derivation depends on no one
    ///      having called anything.
    ///
    ///      v1 has exactly one operator, so this mapping holds one entry. It is a
    ///      mapping rather than bare counters so the ABI survives a future
    ///      operator registry without changing shape.
    struct Stats {
        uint64 requested;
        uint64 fulfilled;
        uint64 expired;
    }

    mapping(uint256 => Request) public requests;
    mapping(uint256 => bytes32) public randomnessOf;
    mapping(bytes32 => Stats) public stats;

    uint256 public nextRequestId = 1;

    // =====================================================================
    //                              events
    // =====================================================================

    event RandomnessRequested(
        uint256 indexed requestId, address indexed requester, uint256 requestBlock, uint32 callbackGasLimit
    );
    event RandomnessFulfilled(uint256 indexed requestId, bytes32 randomness, bool callbackSucceeded);
    event RequestExpired(uint256 indexed requestId, address indexed requester);

    // =====================================================================
    //                              errors
    // =====================================================================

    error CallbackGasTooHigh();
    error NoSuchRequest();
    error RequestNotPending();
    error TooEarly();
    error RequestExpiredError();
    error NotYetExpired();
    error SeedUnavailable();
    error InvalidSignature();
    error InsufficientGasForCallback();
    error TimeoutExceedsBlockhashWindow();

    // =====================================================================
    //                            construction
    // =====================================================================

    /// @param pubkey The operator's BLS public key in G2.
    /// @dev Runs the FULL validation, including the [R]P subgroup check, and
    ///      reverts if the key is malformed. This is the only place a key can
    ///      enter the contract, which is what makes the cheap fulfilment path
    ///      below sound.
    constructor(BN254.G2Point memory pubkey) {
        // Deploy-time assertion: expiry must fire before the seed's block hash
        // ages out, or an expired request could mean "unfulfillable" rather than
        // "unanswered" and the miss counter would stop meaning anything.
        if (REQUEST_TIMEOUT_BLOCKS >= BLOCKHASH_WINDOW) revert TimeoutExceedsBlockhashWindow();

        BN254.validateG2(pubkey);

        pubkeyX0 = pubkey.x_c0;
        pubkeyX1 = pubkey.x_c1;
        pubkeyY0 = pubkey.y_c0;
        pubkeyY1 = pubkey.y_c1;
        operatorId = keccak256(abi.encode(pubkey.x_c0, pubkey.x_c1, pubkey.y_c0, pubkey.y_c1));
    }

    /// @notice The operator public key this contract verifies against.
    function operatorPubkey() public view returns (BN254.G2Point memory) {
        return BN254.G2Point(pubkeyX0, pubkeyX1, pubkeyY0, pubkeyY1);
    }

    // =====================================================================
    //                              request
    // =====================================================================

    /// @notice Request randomness. The callback goes to `msg.sender`.
    /// @param callbackGasLimit Gas budget for the consumer callback.
    /// @return requestId Identifier for this request.
    function requestRandomness(uint32 callbackGasLimit) external returns (uint256 requestId) {
        if (callbackGasLimit > MAX_CALLBACK_GAS) revert CallbackGasTooHigh();

        requestId = nextRequestId++;
        requests[requestId] = Request({
            requester: msg.sender,
            requestBlock: uint48(block.number),
            callbackGasLimit: callbackGasLimit,
            status: Status.Pending
        });

        unchecked {
            ++stats[operatorId].requested;
        }

        emit RandomnessRequested(requestId, msg.sender, block.number, callbackGasLimit);
    }

    // =====================================================================
    //                              seed
    // =====================================================================

    /// @notice The seed for a request: keccak256(requestId, requester, blockhash(requestBlock + 1)).
    ///
    /// @dev The block hash is of a block that did not exist when the request was
    ///      made, so a requester cannot grind the seed. It is fixed by
    ///      `requestBlock + 1` and does not depend on when fulfilment happens, so
    ///      the operator cannot grind by choosing a submission time either.
    ///
    ///      Reverts rather than returning a seed derived from a zero block hash.
    ///      A zero hash would silently produce a well-formed but meaningless seed,
    ///      which is precisely the kind of quiet degradation this contract must
    ///      not have. In practice `REQUEST_TIMEOUT_BLOCKS` makes this unreachable
    ///      through `fulfillRandomness`; the check is the backstop.
    function seedOf(uint256 requestId) public view returns (bytes32) {
        Request memory r = requests[requestId];
        if (r.status == Status.None) revert NoSuchRequest();

        uint256 seedBlock = uint256(r.requestBlock) + 1;
        if (block.number <= seedBlock) revert TooEarly();

        bytes32 bh = blockhash(seedBlock);
        if (bh == bytes32(0)) revert SeedUnavailable();

        return keccak256(abi.encode(requestId, r.requester, bh));
    }

    /// @notice The exact byte string the operator must sign for this request.
    /// @dev Domain-separated by chain id and contract address so a signature
    ///      cannot be replayed against another deployment or another chain.
    function fulfilmentMessage(uint256 requestId) public view returns (bytes memory) {
        return abi.encodePacked(
            "sortition/v1/fulfil", block.chainid, address(this), requestId, seedOf(requestId)
        );
    }

    // =====================================================================
    //                             fulfilment
    // =====================================================================

    /// @notice Fulfil a request with the operator's BLS signature over its message.
    ///
    /// @dev Callable by anyone. The signature is the authorisation — there is no
    ///      caller check, because a valid signature can only have come from the
    ///      operator's key and an invalid one is rejected. This lets a relayer
    ///      submit on the operator's behalf.
    ///
    ///      WHY THIS USES `verifyPrevalidatedKey` AND THAT IS NOT A MISSING CHECK:
    ///
    ///      `verifyPrevalidatedKey` skips the G2 subgroup check on the public key.
    ///      That check costs ~1.78M gas and is 93% of a full `verify`. It is
    ///      skipped here because it was already run, in full, on this exact key,
    ///      in the constructor — and the key is `immutable`, so it cannot have
    ///      changed since and no other code path can install a different one.
    ///      Validating it again on every fulfilment would be paying 1.78M gas to
    ///      re-derive an answer that is fixed for the lifetime of the contract.
    ///
    ///      The signature itself is fully validated on every call: it is in G1,
    ///      whose cofactor is 1, so an on-curve check is a complete subgroup
    ///      check for it.
    ///
    ///      If a rotation path is ever added, this reasoning collapses unless that
    ///      path runs `BN254.validateG2` and requests are bound to a key epoch.
    function fulfillRandomness(uint256 requestId, BN254.G1Point calldata signature) external {
        Request memory r = requests[requestId];
        if (r.status == Status.None) revert NoSuchRequest();
        if (r.status != Status.Pending) revert RequestNotPending();
        if (block.number > uint256(r.requestBlock) + REQUEST_TIMEOUT_BLOCKS) revert RequestExpiredError();

        bytes memory message = fulfilmentMessage(requestId);

        bool ok = BN254.verifyPrevalidatedKey(operatorPubkey(), message, signature);
        if (!ok) revert InvalidSignature();

        bytes32 randomness = keccak256(abi.encode(signature.x, signature.y));

        // Effects before interaction: the record is final before the consumer is
        // given control, so a reverting or reentering consumer cannot change it.
        requests[requestId].status = Status.Fulfilled;
        randomnessOf[requestId] = randomness;
        unchecked {
            ++stats[operatorId].fulfilled;
        }

        bool callbackSucceeded = _callback(requestId, r, randomness);

        emit RandomnessFulfilled(requestId, randomness, callbackSucceeded);
    }

    /// @dev Gas-limited callback. Its failure is isolated and never prevents the
    ///      fulfilment from being recorded.
    function _callback(uint256 requestId, Request memory r, bytes32 randomness) private returns (bool) {
        uint256 cbGas = r.callbackGasLimit;
        if (cbGas == 0) return false;

        // EIP-150 forwards at most 63/64 of remaining gas, so require enough that
        // the consumer genuinely receives the budget it asked for. Without this a
        // fulfiller could starve the callback while still recording a fulfilment.
        if (gasleft() < (cbGas * 64) / 63 + CALLBACK_GAS_BUFFER) revert InsufficientGasForCallback();

        (bool ok,) = r.requester.call{gas: cbGas}(
            abi.encodeCall(IRandomnessConsumer.receiveRandomness, (requestId, randomness))
        );
        return ok;
    }

    // =====================================================================
    //                              expiry
    // =====================================================================

    /// @notice Mark an unanswered request as expired.
    ///
    /// @dev Callable by anyone. This is the accountability mechanism: it is the
    ///      on-chain, permanent record that the operator was asked and did not
    ///      answer. Suppression is not prevented by this design — it is made
    ///      countable, and this is where the count happens.
    function expireRequest(uint256 requestId) external {
        Request memory r = requests[requestId];
        if (r.status == Status.None) revert NoSuchRequest();
        if (r.status != Status.Pending) revert RequestNotPending();
        if (block.number <= uint256(r.requestBlock) + REQUEST_TIMEOUT_BLOCKS) revert NotYetExpired();

        requests[requestId].status = Status.Expired;
        unchecked {
            ++stats[operatorId].expired;
        }

        emit RequestExpired(requestId, r.requester);
    }

    // =====================================================================
    //                              views
    // =====================================================================

    /// @notice Fulfilment record for this contract's operator.
    /// @dev `expired` under-reports and can be permanently wrong. See the NatSpec
    ///      on `Stats`. Derive the real miss rate from events.
    function operatorStats() external view returns (uint64 requested, uint64 fulfilled, uint64 expired) {
        Stats memory s = stats[operatorId];
        return (s.requested, s.fulfilled, s.expired);
    }

    /// @notice Requests that were made, not answered, and not yet marked expired.
    /// @dev DO NOT read this as "requests still in flight". It mixes requests
    ///      inside the timeout window, which are not misses, with requests past
    ///      the timeout that nobody expired, which are. See the NatSpec on
    ///      `Stats`. Use events to tell the two apart.
    function pendingCount() external view returns (uint256) {
        Stats memory s = stats[operatorId];
        return uint256(s.requested) - uint256(s.fulfilled) - uint256(s.expired);
    }

    function isExpired(uint256 requestId) external view returns (bool) {
        Request memory r = requests[requestId];
        if (r.status == Status.Expired) return true;
        if (r.status != Status.Pending) return false;
        return block.number > uint256(r.requestBlock) + REQUEST_TIMEOUT_BLOCKS;
    }
}
