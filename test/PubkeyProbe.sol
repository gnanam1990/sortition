// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BN254} from "../src/BN254.sol";

/// @notice Validates a candidate operator public key using the EXACT Solidity the
///         coordinator's constructor will run, via `eth_call --create`. No key,
///         no deployment, nothing mined.
/// @dev Returns (onCurve, inSubgroup, wouldConstructorAccept).
contract PubkeyProbe {
    constructor(BN254.G2Point memory pk) {
        bool onCurve;
        bool inSub;
        bool accepted;

        // Reduced-coordinate and infinity checks mirror validateG2OnCurve.
        bool reduced = pk.x_c0 < BN254.P && pk.x_c1 < BN254.P && pk.y_c0 < BN254.P && pk.y_c1 < BN254.P;
        bool infinity = pk.x_c0 == 0 && pk.x_c1 == 0 && pk.y_c0 == 0 && pk.y_c1 == 0;

        if (reduced && !infinity) {
            onCurve = BN254.isOnCurveG2(pk);
            if (onCurve) {
                inSub = BN254.isInSubgroupG2(pk);
            }
        }
        accepted = reduced && !infinity && onCurve && inSub;

        bytes memory data = abi.encode(reduced, infinity, onCurve, inSub, accepted);
        assembly { return(add(data, 32), mload(data)) }
    }
}
