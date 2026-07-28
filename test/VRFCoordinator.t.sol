// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {BN254} from "../src/BN254.sol";
import {VRFCoordinator, IRandomnessConsumer} from "../src/VRFCoordinator.sol";
import {Vectors} from "./Vectors.sol";

/// @dev Test-only BLS signer. Signing is [sk]·H(m), a G1 scalar multiplication,
///      which is precompile 0x07 — so the tests can produce real signatures over
///      messages that depend on runtime values rather than relying on static
///      vectors that could not cover chain id, contract address or block hash.
library TestSigner {
    function sign(uint256 sk, bytes memory message) internal view returns (BN254.G1Point memory) {
        return ecmul(BN254.hashToG1(message), sk);
    }

    function ecmul(BN254.G1Point memory p, uint256 s) internal view returns (BN254.G1Point memory r) {
        uint256[3] memory input = [p.x, p.y, s];
        uint256[2] memory out;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x07, input, 96, out, 64)
        }
        require(ok, "ecmul failed");
        r = BN254.G1Point(out[0], out[1]);
    }
}

// ---------------------------------------------------------------- consumers

contract GoodConsumer is IRandomnessConsumer {
    uint256 public lastId;
    bytes32 public lastRandomness;
    uint256 public callCount;

    /// @dev Lets the consumer be the requester, so the callback targets it.
    ///      Used by tools/e2e_local.py; the unit tests prank instead.
    function request(VRFCoordinator c, uint32 g) external returns (uint256) {
        return c.requestRandomness(g);
    }

    function receiveRandomness(uint256 requestId, bytes32 randomness) external override {
        lastId = requestId;
        lastRandomness = randomness;
        ++callCount;
    }
}

contract RevertingConsumer is IRandomnessConsumer {
    function receiveRandomness(uint256, bytes32) external pure override {
        revert("consumer is broken");
    }
}

contract GasGuzzlingConsumer is IRandomnessConsumer {
    uint256 public sink;

    function receiveRandomness(uint256, bytes32) external override {
        // Burn every drop of the forwarded budget.
        while (true) {
            sink++;
        }
    }
}

/// @dev Tries to fulfil the same request again from inside the callback.
contract ReentrantConsumer is IRandomnessConsumer {
    VRFCoordinator immutable coord;
    BN254.G1Point sig;
    uint256 target;
    bool public reentryReverted;

    constructor(VRFCoordinator c) {
        coord = c;
    }

    function arm(uint256 id, BN254.G1Point memory s) external {
        target = id;
        sig = s;
    }

    function receiveRandomness(uint256, bytes32) external override {
        try coord.fulfillRandomness(target, sig) {
            reentryReverted = false;
        } catch {
            reentryReverted = true;
        }
    }
}

// ---------------------------------------------------------------- the tests

contract VRFCoordinatorTest is Test {
    using TestSigner for uint256;

    VRFCoordinator coord;
    GoodConsumer good;

    uint256 constant SK = Vectors.TEST_ONLY_SECRET_SCALAR;

    function setUp() public {
        coord = new VRFCoordinator(Vectors.pubkey());
        good = new GoodConsumer();
        vm.roll(1000);
    }

    // ---------------------------------------------------------- helpers

    /// @dev The block a request was recorded at, read back from contract storage.
    ///
    ///      Deliberately NOT `uint256 b = block.number` in the caller. Under
    ///      via_ir the optimiser treats `block.number` as constant within a
    ///      function and re-materialises the NUMBER opcode at each use — so a
    ///      local captured before `vm.roll` silently reads the NEW block number
    ///      afterwards. That produced `roll(n+1)` followed by `setBlockhash(n+2)`
    ///      from a single `reqBlock + 1` expression. An external staticcall cannot
    ///      be folded that way, so this is stable.
    function _requestBlockOf(uint256 id) internal view returns (uint256) {
        (, uint48 rb,,) = coord.requests(id);
        return uint256(rb);
    }

    /// @dev Request, then advance far enough that the seed block hash exists.
    function _request(address who, uint32 cbGas) internal returns (uint256 id, uint256 reqBlock) {
        vm.prank(who);
        id = coord.requestRandomness(cbGas);
        reqBlock = _requestBlockOf(id);

        // Give block reqBlock+1 a hash. setBlockhash only works for the current
        // block, so roll onto it first, then move past it.
        vm.roll(reqBlock + 1);
        vm.setBlockhash(reqBlock + 1, keccak256(abi.encode("seedblock", id)));
        vm.roll(reqBlock + 2);
    }

    function _sign(uint256 id) internal view returns (BN254.G1Point memory) {
        return TestSigner.sign(SK, coord.fulfilmentMessage(id));
    }

    // =================================================================
    //   KEY HANDLING — the property everything else rests on
    // =================================================================

    /// @dev The one and only path by which a key can enter the contract runs the
    ///      full subgroup check. A key on the twist but outside the R-order
    ///      subgroup must not be installable.
    function test_Constructor_RejectsWrongSubgroupKey() public {
        vm.expectRevert(BN254.PointNotInSubgroup.selector);
        new VRFCoordinator(Vectors.wrongSubgroupPubkey());
    }

    function test_Constructor_RejectsOffCurveKey() public {
        BN254.G2Point memory bad = Vectors.pubkey();
        bad.y_c0 = bad.y_c0 ^ 1;
        vm.expectRevert(BN254.PointNotOnCurve.selector);
        new VRFCoordinator(bad);
    }

    function test_Constructor_RejectsInfinityKey() public {
        vm.expectRevert(BN254.PointIsInfinity.selector);
        new VRFCoordinator(BN254.G2Point(0, 0, 0, 0));
    }

    function test_RegisteredKeyIsTheOneVerifiedAgainst() public view {
        BN254.G2Point memory k = coord.operatorPubkey();
        BN254.G2Point memory want = Vectors.pubkey();
        assertEq(k.x_c0, want.x_c0);
        assertEq(k.x_c1, want.x_c1);
        assertEq(k.y_c0, want.y_c0);
        assertEq(k.y_c1, want.y_c1);
        assertEq(coord.operatorId(), keccak256(abi.encode(want.x_c0, want.x_c1, want.y_c0, want.y_c1)));
    }

    /// @dev The key is `immutable`, so the compiler guarantees no post-construction
    ///      write exists. This asserts the ABI offers nothing that could set one —
    ///      a regression guard for anyone later tempted to add a rotation path
    ///      without reading the NatSpec.
    function test_NoKeyMutatingFunctionInAbi() public view {
        string[5] memory forbidden =
            ["setPubkey(uint256,uint256,uint256,uint256)", "rotateKey(uint256,uint256,uint256,uint256)", "setOperator(address)", "registerKey(uint256,uint256,uint256,uint256)", "updatePubkey(uint256,uint256,uint256,uint256)"];
        for (uint256 i = 0; i < forbidden.length; i++) {
            bytes4 sel = bytes4(keccak256(bytes(forbidden[i])));
            (bool ok,) = address(coord).staticcall(abi.encodePacked(sel));
            assertFalse(ok, "a key-mutating selector responded");
        }
    }

    // =================================================================
    //   HAPPY PATH
    // =================================================================

    function test_FulfilmentWithValidSignature() public {
        (uint256 id,) = _request(address(good), 100_000);

        BN254.G1Point memory sig = _sign(id);
        coord.fulfillRandomness(id, sig);

        assertEq(uint256(_status(id)), uint256(VRFCoordinator.Status.Fulfilled));
        assertEq(good.callCount(), 1, "callback not delivered");
        assertEq(good.lastId(), id);
        assertEq(good.lastRandomness(), keccak256(abi.encode(sig.x, sig.y)));
        assertEq(coord.randomnessOf(id), good.lastRandomness());

        (uint64 req, uint64 ful, uint64 exp) = coord.operatorStats();
        assertEq(req, 1);
        assertEq(ful, 1);
        assertEq(exp, 0);
    }

    function test_RequestIncrementsRequestedCounter() public {
        vm.prank(address(good));
        coord.requestRandomness(0);
        vm.prank(address(good));
        coord.requestRandomness(0);
        (uint64 req,,) = coord.operatorStats();
        assertEq(req, 2);
        assertEq(coord.pendingCount(), 2);
    }

    /// @dev The output must be a function of the seed, so two requests in
    ///      different blocks must not collide.
    function test_DistinctRequestsProduceDistinctRandomness() public {
        (uint256 id1,) = _request(address(good), 100_000);
        coord.fulfillRandomness(id1, _sign(id1));
        bytes32 r1 = coord.randomnessOf(id1);

        (uint256 id2,) = _request(address(good), 100_000);
        coord.fulfillRandomness(id2, _sign(id2));
        bytes32 r2 = coord.randomnessOf(id2);

        assertTrue(r1 != r2, "distinct requests produced identical randomness");
    }

    // =================================================================
    //   FORGERY AND REJECTION
    // =================================================================

    function test_ForgedSignature_Rejected() public {
        (uint256 id,) = _request(address(good), 100_000);

        // Signed with the wrong scalar: a structurally valid G1 point, wrong value.
        BN254.G1Point memory forged = TestSigner.sign(SK + 1, coord.fulfilmentMessage(id));

        vm.expectRevert(VRFCoordinator.InvalidSignature.selector);
        coord.fulfillRandomness(id, forged);

        assertEq(uint256(_status(id)), uint256(VRFCoordinator.Status.Pending), "state changed on rejection");
        (, uint64 ful,) = coord.operatorStats();
        assertEq(ful, 0, "forgery counted as a fulfilment");
        assertEq(good.callCount(), 0, "callback fired on a forgery");
        assertEq(coord.randomnessOf(id), bytes32(0), "randomness stored for a forgery");
    }

    /// @dev A signature valid for a DIFFERENT request must not fulfil this one.
    ///      This is what the request id inside the signed message buys.
    function test_SignatureFromAnotherRequest_Rejected() public {
        (uint256 id1,) = _request(address(good), 100_000);
        (uint256 id2,) = _request(address(good), 100_000);

        BN254.G1Point memory sigFor1 = _sign(id1);
        vm.expectRevert(VRFCoordinator.InvalidSignature.selector);
        coord.fulfillRandomness(id2, sigFor1);
    }

    function test_MalformedSignature_Reverts() public {
        (uint256 id,) = _request(address(good), 100_000);
        BN254.G1Point memory sig = _sign(id);
        sig.y = sig.y ^ 1; // off curve

        vm.expectRevert(BN254.PointNotOnCurve.selector);
        coord.fulfillRandomness(id, sig);
    }

    function test_ZeroSignature_Reverts() public {
        (uint256 id,) = _request(address(good), 100_000);
        vm.expectRevert(BN254.PointIsInfinity.selector);
        coord.fulfillRandomness(id, BN254.G1Point(0, 0));
    }

    function test_DoubleFulfilment_Rejected() public {
        (uint256 id,) = _request(address(good), 100_000);
        BN254.G1Point memory sig = _sign(id);

        coord.fulfillRandomness(id, sig);

        vm.expectRevert(VRFCoordinator.RequestNotPending.selector);
        coord.fulfillRandomness(id, sig);

        assertEq(good.callCount(), 1, "callback delivered twice");
        (, uint64 ful,) = coord.operatorStats();
        assertEq(ful, 1, "fulfilled counter double-counted");
    }

    function test_UnknownRequest_Rejected() public {
        BN254.G1Point memory sig = BN254.generatorG1();
        vm.expectRevert(VRFCoordinator.NoSuchRequest.selector);
        coord.fulfillRandomness(9999, sig);
    }

    // =================================================================
    //   CONSUMER ISOLATION
    // =================================================================

    function test_RevertingConsumer_DoesNotBlockFulfilment() public {
        RevertingConsumer bad = new RevertingConsumer();
        (uint256 id,) = _request(address(bad), 100_000);

        coord.fulfillRandomness(id, _sign(id));

        assertEq(uint256(_status(id)), uint256(VRFCoordinator.Status.Fulfilled), "fulfilment blocked by consumer");
        (, uint64 ful,) = coord.operatorStats();
        assertEq(ful, 1);
        assertTrue(coord.randomnessOf(id) != bytes32(0), "randomness not recorded");
    }

    function test_GasGuzzlingConsumer_DoesNotBlockFulfilment() public {
        GasGuzzlingConsumer hog = new GasGuzzlingConsumer();
        (uint256 id,) = _request(address(hog), 200_000);

        coord.fulfillRandomness(id, _sign(id));

        assertEq(uint256(_status(id)), uint256(VRFCoordinator.Status.Fulfilled));
        assertTrue(coord.randomnessOf(id) != bytes32(0));
    }

    /// @dev State is final before the consumer gets control, so reentry finds the
    ///      request already fulfilled and is rejected.
    function test_ReentrantConsumer_CannotDoubleFulfil() public {
        ReentrantConsumer re = new ReentrantConsumer(coord);
        (uint256 id,) = _request(address(re), 500_000);

        BN254.G1Point memory sig = _sign(id);
        re.arm(id, sig);
        coord.fulfillRandomness(id, sig);

        assertTrue(re.reentryReverted(), "reentrant fulfilment was not rejected");
        (, uint64 ful,) = coord.operatorStats();
        assertEq(ful, 1, "reentry double-counted a fulfilment");
    }

    function test_CallbackGasCeilingEnforced() public {
        // Read the ceiling BEFORE arming expectRevert: the cheatcode applies to
        // the next call, and an argument that is itself a staticcall would
        // consume it.
        uint32 tooMuch = uint32(coord.MAX_CALLBACK_GAS() + 1);
        vm.expectRevert(VRFCoordinator.CallbackGasTooHigh.selector);
        coord.requestRandomness(tooMuch);
    }

    /// @dev A fulfiller cannot starve the callback while still recording a
    ///      fulfilment: too little gas forwarded means the whole call reverts.
    function test_InsufficientGasForCallback_Reverts() public {
        (uint256 id,) = _request(address(good), 1_000_000);
        BN254.G1Point memory sig = _sign(id);

        vm.expectRevert(VRFCoordinator.InsufficientGasForCallback.selector);
        coord.fulfillRandomness{gas: 700_000}(id, sig);
    }

    // =================================================================
    //   EXPIRY
    // =================================================================

    function test_Expiry_IncrementsMissCounter() public {
        (uint256 id, uint256 reqBlock) = _request(address(good), 100_000);

        vm.roll(reqBlock + coord.REQUEST_TIMEOUT_BLOCKS() + 1);
        assertTrue(coord.isExpired(id), "should be expired");

        coord.expireRequest(id);

        assertEq(uint256(_status(id)), uint256(VRFCoordinator.Status.Expired));
        (uint64 req, uint64 ful, uint64 exp) = coord.operatorStats();
        assertEq(req, 1);
        assertEq(ful, 0);
        assertEq(exp, 1, "miss not counted");
        assertEq(coord.pendingCount(), 0);
    }

    function test_ExpireBeforeTimeout_Rejected() public {
        (uint256 id, uint256 reqBlock) = _request(address(good), 100_000);
        vm.roll(reqBlock + coord.REQUEST_TIMEOUT_BLOCKS());
        vm.expectRevert(VRFCoordinator.NotYetExpired.selector);
        coord.expireRequest(id);
    }

    function test_FulfilAfterExpiry_Rejected() public {
        (uint256 id, uint256 reqBlock) = _request(address(good), 100_000);
        BN254.G1Point memory sig = _sign(id);

        vm.roll(reqBlock + coord.REQUEST_TIMEOUT_BLOCKS() + 1);

        vm.expectRevert(VRFCoordinator.RequestExpiredError.selector);
        coord.fulfillRandomness(id, sig);
    }

    function test_ExpireAlreadyFulfilled_Rejected() public {
        (uint256 id, uint256 reqBlock) = _request(address(good), 100_000);
        coord.fulfillRandomness(id, _sign(id));

        vm.roll(reqBlock + coord.REQUEST_TIMEOUT_BLOCKS() + 1);
        vm.expectRevert(VRFCoordinator.RequestNotPending.selector);
        coord.expireRequest(id);
    }

    function test_DoubleExpiry_Rejected() public {
        (uint256 id, uint256 reqBlock) = _request(address(good), 100_000);
        vm.roll(reqBlock + coord.REQUEST_TIMEOUT_BLOCKS() + 1);
        coord.expireRequest(id);

        vm.expectRevert(VRFCoordinator.RequestNotPending.selector);
        coord.expireRequest(id);

        (,, uint64 exp) = coord.operatorStats();
        assertEq(exp, 1, "miss double-counted");
    }

    // =================================================================
    //   THE BLOCKHASH WINDOW
    // =================================================================

    /// @dev Fulfilment beyond the 256-block window is rejected as EXPIRED, not as
    ///      a seed failure. That ordering is the whole point of setting
    ///      REQUEST_TIMEOUT_BLOCKS below 256: the request becomes un-fulfillable
    ///      for an attributable reason before it becomes un-fulfillable for a
    ///      mechanical one. The two must never be confusable, because the expiry
    ///      counter is what the trust model reads.
    function test_BeyondBlockhashWindow_RejectedAsExpiredNotAsSeedFailure() public {
        (uint256 id, uint256 reqBlock) = _request(address(good), 100_000);
        BN254.G1Point memory sig = _sign(id);

        vm.roll(reqBlock + 300); // past both the timeout and the 256-block window

        vm.expectRevert(VRFCoordinator.RequestExpiredError.selector);
        coord.fulfillRandomness(id, sig);
    }

    /// @dev And the underlying seed really is gone by then — so the guard above is
    ///      load-bearing, not decorative. Without the timeout ordering this is the
    ///      error a late fulfiller would hit.
    function test_SeedUnavailableOnceBlockhashAgesOut() public {
        (uint256 id, uint256 reqBlock) = _request(address(good), 100_000);

        coord.seedOf(id); // fine now

        vm.roll(reqBlock + 300);
        vm.expectRevert(VRFCoordinator.SeedUnavailable.selector);
        coord.seedOf(id);
    }

    /// @dev The timeout must stay strictly inside the measured 256-block window.
    function test_TimeoutIsInsideBlockhashWindow() public view {
        assertLt(coord.REQUEST_TIMEOUT_BLOCKS(), 256, "timeout outlives the block hash");
        assertLt(coord.REQUEST_TIMEOUT_BLOCKS() + 1, 257, "seed could age out before expiry");
    }

    function test_SeedBeforeItExists_Reverts() public {
        vm.prank(address(good));
        uint256 id = coord.requestRandomness(0);
        vm.expectRevert(VRFCoordinator.TooEarly.selector);
        coord.seedOf(id);
    }

    /// @dev The seed depends on the block hash, which does not exist when the
    ///      request is made. This is what stops a requester grinding.
    function test_SeedDependsOnFutureBlockhash() public {
        vm.prank(address(good));
        uint256 id = coord.requestRandomness(0);
        uint256 reqBlock = _requestBlockOf(id);

        vm.roll(reqBlock + 1);
        vm.setBlockhash(reqBlock + 1, keccak256("hash A"));
        vm.roll(reqBlock + 2);
        bytes32 seedA = coord.seedOf(id);

        // Rewind and give that block a different hash.
        vm.roll(reqBlock + 1);
        vm.setBlockhash(reqBlock + 1, keccak256("hash B"));
        vm.roll(reqBlock + 2);
        bytes32 seedB = coord.seedOf(id);

        assertTrue(seedA != seedB, "seed does not depend on the block hash");
    }

    // =================================================================
    //   GAS
    // =================================================================

    function test_Gas_FullFulfilment() public {
        (uint256 id,) = _request(address(good), 100_000);
        BN254.G1Point memory sig = _sign(id);

        uint256 g0 = gasleft();
        coord.fulfillRandomness(id, sig);
        uint256 used = g0 - gasleft();

        (uint256 id2,) = _request(address(good), 0);
        BN254.G1Point memory sig2 = _sign(id2);
        g0 = gasleft();
        coord.fulfillRandomness(id2, sig2);
        uint256 usedNoCb = g0 - gasleft();

        vm.prank(address(good));
        g0 = gasleft();
        coord.requestRandomness(100_000);
        uint256 usedReq = g0 - gasleft();

        console.log("--- measured gas");
        console.log("requestRandomness()                    :", usedReq);
        console.log("fulfillRandomness(), no callback       :", usedNoCb);
        console.log("fulfillRandomness(), 100k gas consumer :", used);
    }

    // ---------------------------------------------------------- internal

    function _status(uint256 id) internal view returns (VRFCoordinator.Status) {
        (,,, VRFCoordinator.Status s) = coord.requests(id);
        return s;
    }
}
