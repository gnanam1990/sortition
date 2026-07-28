// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {BN254} from "../src/BN254.sol";
import {VRFCoordinator} from "../src/VRFCoordinator.sol";
import {ExampleConsumer} from "../src/ExampleConsumer.sol";

/// @notice Deploys the coordinator and a reference consumer.
///
/// @dev The operator public key comes from the environment, never from this
///      repository. The constructor runs the full subgroup check, so a malformed
///      key reverts the deployment rather than producing a coordinator that can
///      never be fulfilled.
///
///      Arc fee note: this deployment is ~3.28M gas, far above the 100,000 gas
///      threshold at which Arc requires the priority fee to be collapsed by 1e9.
///      Pass `--priority-gas-price 1` (one wei), or the transaction can hit
///      maxGasLimit and fail. Let forge read the base fee fresh; never pin it.
contract Deploy is Script {
    function run() external {
        BN254.G2Point memory pk = BN254.G2Point(
            vm.envUint("SORTITION_PK_X_C0"),
            vm.envUint("SORTITION_PK_X_C1"),
            vm.envUint("SORTITION_PK_Y_C0"),
            vm.envUint("SORTITION_PK_Y_C1")
        );

        vm.startBroadcast();
        VRFCoordinator coordinator = new VRFCoordinator(pk);
        ExampleConsumer consumer = new ExampleConsumer(coordinator);
        vm.stopBroadcast();

        console.log("VRFCoordinator :", address(coordinator));
        console.log("ExampleConsumer:", address(consumer));
        console.log("operatorId     :");
        console.logBytes32(coordinator.operatorId());
        console.log("timeout blocks :", coordinator.REQUEST_TIMEOUT_BLOCKS());
    }
}
