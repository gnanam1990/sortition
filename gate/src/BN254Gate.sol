// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BN254Gate — gate check for the standard BN254 (alt_bn128) precompiles.
/// @notice Calls 0x06 / 0x07 / 0x08 with vectors whose answers are known independently
///         of any chain, so a WRONG result is distinguishable from a FAILURE.
///         Every result is written to storage and read back from chain.
contract BN254Gate {
    // ---- G1 generator and its negation ------------------------------------
    uint256 constant P    = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant G1X  = 1;
    uint256 constant G1Y  = 2;
    uint256 constant NG1Y = P - 2; // -G1 = (1, p-2)

    // ---- G2 generator, EIP-197 encoding: (x_imag, x_real, y_imag, y_real) --
    uint256 constant G2X1 = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2;
    uint256 constant G2X0 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed;
    uint256 constant G2Y1 = 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b;
    uint256 constant G2Y0 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa;

    // ---- results, all read back from storage ------------------------------
    bool    public ran;

    bool    public ecAddOk;      uint256 public ecAddGas;      uint256 public ecAddX;   uint256 public ecAddY;
    bool    public ecMulOk;      uint256 public ecMulGas;      uint256 public ecMulX;   uint256 public ecMulY;
    // 2-pair check, product == 1  -> must return 1
    bool    public pairTrueOk;   uint256 public pairTrueGas;   uint256 public pairTrueOut;
    // 2-pair check, product != 1  -> must return 0. This is the anti-stub control.
    bool    public pairFalseOk;  uint256 public pairFalseGas;  uint256 public pairFalseOut;
    // 4-pair check, product == 1  -> must return 1. Delta vs 2-pair = marginal cost per pairing.
    bool    public pair4Ok;      uint256 public pair4Gas;      uint256 public pair4Out;

    /// @dev staticcall a precompile, measuring the gas the EVM actually charged.
    function _probe(address precompile, bytes memory input, uint256 outLen)
        internal
        view
        returns (bool ok, uint256 gasUsed, bytes memory out)
    {
        out = new bytes(outLen);            // allocate before the meter starts
        uint256 before = gasleft();
        assembly {
            ok := staticcall(gas(), precompile, add(input, 32), mload(input), add(out, 32), outLen)
        }
        gasUsed = before - gasleft();
    }

    function _g2() internal pure returns (bytes memory) {
        return abi.encodePacked(G2X1, G2X0, G2Y1, G2Y0);
    }

    function run() external {
        _runAll();
    }

    function _runAll() internal {
        bool ok;
        uint256 g;
        bytes memory out;

        // -- 0x06 ecadd:  G1 + G1  ==  2*G1 ---------------------------------
        (ok, g, out) = _probe(address(0x06), abi.encodePacked(G1X, G1Y, G1X, G1Y), 64);
        ecAddOk = ok; ecAddGas = g;
        if (ok) { (ecAddX, ecAddY) = abi.decode(out, (uint256, uint256)); }

        // -- 0x07 ecmul:  G1 * 2   ==  2*G1 (must agree with ecadd) ---------
        (ok, g, out) = _probe(address(0x07), abi.encodePacked(G1X, G1Y, uint256(2)), 64);
        ecMulOk = ok; ecMulGas = g;
        if (ok) { (ecMulX, ecMulY) = abi.decode(out, (uint256, uint256)); }

        bytes memory g2 = _g2();

        // -- 0x08 ecpairing, POSITIVE: e(G1,G2)*e(-G1,G2) == 1 -> 1 ---------
        (ok, g, out) = _probe(
            address(0x08),
            abi.encodePacked(G1X, G1Y, g2, G1X, NG1Y, g2),
            32
        );
        pairTrueOk = ok; pairTrueGas = g;
        if (ok) { pairTrueOut = abi.decode(out, (uint256)); }

        // -- 0x08 ecpairing, NEGATIVE: e(G1,G2)^2 != 1 -> 0 -----------------
        //    A stub that always returns 1 fails HERE.
        (ok, g, out) = _probe(
            address(0x08),
            abi.encodePacked(G1X, G1Y, g2, G1X, G1Y, g2),
            32
        );
        pairFalseOk = ok; pairFalseGas = g;
        if (ok) { pairFalseOut = abi.decode(out, (uint256)); }

        // -- 0x08 ecpairing, 4 pairs, product == 1 -> 1 ---------------------
        //    (pair4Gas - pairTrueGas) / 2 = marginal gas per pairing.
        (ok, g, out) = _probe(
            address(0x08),
            abi.encodePacked(G1X, G1Y, g2, G1X, NG1Y, g2, G1X, G1Y, g2, G1X, NG1Y, g2),
            32
        );
        pair4Ok = ok; pair4Gas = g;
        if (ok) { pair4Out = abi.decode(out, (uint256)); }

        ran = true;
    }
}

/// @notice Same probes, run entirely inside a constructor so the results can be
///         obtained through `eth_call --create` with no key and no mined tx.
///         The constructor returns the abi-encoded results in place of runtime code.
contract BN254GateProbe is BN254Gate {
    constructor() {
        _runAll();
        bytes memory data = bytes.concat(
            abi.encode(ecAddOk, ecAddGas, ecAddX, ecAddY),
            abi.encode(ecMulOk, ecMulGas, ecMulX, ecMulY),
            abi.encode(pairTrueOk, pairTrueGas, pairTrueOut),
            abi.encode(pairFalseOk, pairFalseGas, pairFalseOut),
            abi.encode(pair4Ok, pair4Gas, pair4Out)
        );
        assembly { return(add(data, 32), mload(data)) }
    }
}
