// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VRFCoordinator, IRandomnessConsumer} from "./VRFCoordinator.sol";

/// @notice Minimal reference consumer, used to prove the lifecycle end to end.
///
/// @dev Deliberately small. It shows the two things a real consumer must get
///      right and nothing else.
///
///      FIRST: it commits to ONE request id and honours that request's result.
///      Nothing in the coordinator limits how many requests a caller makes, so a
///      consumer that requests repeatedly until it likes the answer has
///      re-introduced grinding at the application layer, above a VRF that
///      prevented it at the protocol layer. Binding to a request before its
///      output is known is the consumer's job.
///
///      SECOND: it accepts the callback only from the coordinator. Without that
///      check anyone could call `receiveRandomness` with a value of their choice.
contract ExampleConsumer is IRandomnessConsumer {
    VRFCoordinator public immutable coordinator;

    uint256 public activeRequestId;
    uint256 public lastRequestId;
    bytes32 public lastRandomness;
    bool public hasResult;

    error NotCoordinator();
    error RequestAlreadyOutstanding();
    error UnexpectedRequest();

    event Drew(uint256 indexed requestId, bytes32 randomness);

    constructor(VRFCoordinator c) {
        coordinator = c;
    }

    /// @notice Make one request and commit to it.
    function draw(uint32 callbackGasLimit) external returns (uint256 id) {
        if (activeRequestId != 0) revert RequestAlreadyOutstanding();
        id = coordinator.requestRandomness(callbackGasLimit);
        activeRequestId = id;
    }

    function receiveRandomness(uint256 requestId, bytes32 randomness) external override {
        if (msg.sender != address(coordinator)) revert NotCoordinator();
        if (requestId != activeRequestId) revert UnexpectedRequest();

        activeRequestId = 0;
        lastRequestId = requestId;
        lastRandomness = randomness;
        hasResult = true;

        emit Drew(requestId, randomness);
    }
}
