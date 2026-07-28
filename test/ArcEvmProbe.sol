// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BN254} from "../src/BN254.sol";
import {Vectors} from "./Vectors.sol";

/// @notice Runs the library's headline paths inside a constructor so the result
///         can be obtained from a live chain with `eth_call --create` — no key,
///         no deployment, nothing mined.
///
/// @dev The forge test suite runs on Foundry's local EVM. This exists to confirm
///      the same code behaves identically on Arc's EVM, which is the only EVM
///      that actually matters here. Same technique as gate/src/BN254Gate.sol.
///
///      Returns, abi-encoded:
///        [0] verify(known-good)        -> must be 1
///        [1] gas charged for the above
///        [2] verify(wrong pubkey)      -> must be 0
///        [3] pairingCheck2 negative    -> must be 0  (the anti-stub vector)
///        [4] isInSubgroupG2(valid)     -> must be 1
///        [5] isInSubgroupG2(wrong sub) -> must be 0
///        [6] verifyPrevalidatedKey     -> must be 1
///        [7] gas charged for the above
contract ArcEvmProbe {
    constructor() {
        uint256 g0;

        g0 = gasleft();
        bool okGood = BN254.verify(Vectors.pubkey(), Vectors.MESSAGE, Vectors.signature());
        uint256 gasVerify = g0 - gasleft();

        bool okWrongKey = BN254.verify(Vectors.wrongPubkey(), Vectors.MESSAGE, Vectors.signature());

        bool negVector = BN254.pairingCheck2(
            BN254.generatorG1(), BN254.generatorG2(), BN254.generatorG1(), BN254.generatorG2()
        );

        bool subValid = BN254.isInSubgroupG2(Vectors.pubkey());
        bool subInvalid = BN254.isInSubgroupG2(Vectors.wrongSubgroupPubkey());

        g0 = gasleft();
        bool okPre =
            BN254.verifyPrevalidatedKey(Vectors.pubkey(), Vectors.MESSAGE, Vectors.signature());
        uint256 gasPre = g0 - gasleft();

        bytes memory data = bytes.concat(
            abi.encode(okGood, gasVerify, okWrongKey, negVector),
            abi.encode(subValid, subInvalid, okPre, gasPre)
        );
        assembly {
            return(add(data, 32), mload(data))
        }
    }
}
