// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {BN254} from "../src/BN254.sol";
import {VRFCoordinator} from "../src/VRFCoordinator.sol";
import {ExampleConsumer} from "../src/ExampleConsumer.sol";
import {Vectors} from "./Vectors.sol";
import {TestSigner} from "./VRFCoordinator.t.sol";

contract ExampleConsumerTest is Test {
    VRFCoordinator coord;
    ExampleConsumer consumer;

    uint256 constant SK = Vectors.TEST_ONLY_SECRET_SCALAR;

    function setUp() public {
        coord = new VRFCoordinator(Vectors.pubkey());
        consumer = new ExampleConsumer(coord);
        vm.roll(1000);
    }

    function _requestBlockOf(uint256 id) internal view returns (uint256) {
        (, uint48 rb,,) = coord.requests(id);
        return uint256(rb);
    }

    function _drawAndAdvance() internal returns (uint256 id) {
        id = consumer.draw(200_000);
        uint256 rb = _requestBlockOf(id);
        vm.roll(rb + 1);
        vm.setBlockhash(rb + 1, keccak256(abi.encode("seed", id)));
        vm.roll(rb + 2);
    }

    function test_FullDrawLifecycle() public {
        uint256 id = _drawAndAdvance();
        assertEq(consumer.activeRequestId(), id, "consumer did not commit to the request");
        assertFalse(consumer.hasResult());

        BN254.G1Point memory sig = TestSigner.sign(SK, coord.fulfilmentMessage(id));
        coord.fulfillRandomness(id, sig);

        assertTrue(consumer.hasResult(), "callback did not land");
        assertEq(consumer.lastRequestId(), id);
        assertEq(consumer.lastRandomness(), keccak256(abi.encode(sig.x, sig.y)));
        assertEq(consumer.activeRequestId(), 0, "commitment not released");
    }

    /// @dev Committing to one request is what stops request-and-discard at the
    ///      application layer. A second draw while one is outstanding is refused.
    function test_CannotHaveTwoOutstandingDraws() public {
        consumer.draw(200_000);
        vm.expectRevert(ExampleConsumer.RequestAlreadyOutstanding.selector);
        consumer.draw(200_000);
    }

    function test_CallbackOnlyFromCoordinator() public {
        _drawAndAdvance();
        vm.expectRevert(ExampleConsumer.NotCoordinator.selector);
        consumer.receiveRandomness(1, keccak256("attacker chosen"));
    }

    function test_CallbackForUnexpectedRequestRejected() public {
        _drawAndAdvance();
        vm.prank(address(coord));
        vm.expectRevert(ExampleConsumer.UnexpectedRequest.selector);
        consumer.receiveRandomness(9999, keccak256("wrong id"));
    }

    /// @dev A consumer that reverts must not take the fulfilment down with it —
    ///      the record still lands even though this callback fails.
    function test_RevertingCallbackStillRecordsFulfilment() public {
        uint256 id = _drawAndAdvance();
        // Force the callback to revert by clearing the commitment behind its
        // back. activeRequestId is slot 0 — `coordinator` is immutable and so
        // lives in code, not storage. Confirmed with `forge inspect ... storage`.
        vm.store(address(consumer), bytes32(uint256(0)), bytes32(uint256(0)));
        assertEq(consumer.activeRequestId(), 0, "commitment not actually cleared");

        BN254.G1Point memory sig = TestSigner.sign(SK, coord.fulfilmentMessage(id));
        coord.fulfillRandomness(id, sig);

        (,,, VRFCoordinator.Status s) = coord.requests(id);
        assertEq(uint256(s), uint256(VRFCoordinator.Status.Fulfilled));
        assertFalse(consumer.hasResult(), "callback should have reverted");
    }
}
