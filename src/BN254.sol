// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BN254 — BLS signature verification over the alt_bn128 curve.
/// @notice Reduces a BLS verification to a single two-pair `ecpairing` call:
///
///             e(sig, G2) · e(−H(m), pubkey) == 1
///
///         Signatures live in G1 (64 bytes), public keys in G2 (128 bytes).
///
/// @dev Every fact this library relies on about the underlying precompiles was
///      measured against Arc testnet (chain 5042002) rather than assumed. See
///      `gate/README.md` for `0x06`/`0x07`/`0x08` and `gate/tools/probe_edges.py`
///      for `0x05` and the input-validation behaviour of `0x08`.
///
///      Measured facts this code depends on:
///        - `0x05` modexp is present and correct (used for the modular sqrt).
///        - `0x08` is present, correct, and priced 45,000 + 34,000·k.
///        - `0x08` rejects off-curve points, non-reduced coordinates, and
///          on-curve-but-wrong-subgroup G2 points.
///        - The G1 cofactor is 1, so on-curve implies correct subgroup in G1.
///
///      The library performs its own validation *before* calling any precompile
///      regardless. The precompile's own rejection is treated as a backstop, not
///      as the guarantee. Rejection is by revert — inputs are never normalised,
///      clamped, or silently coerced into the subgroup.
library BN254 {
    // ------------------------------------------------------------------ field

    /// @dev Base field modulus of alt_bn128.
    uint256 internal constant P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @dev Order of G1 and G2. Also the order of E(Fp) itself: the G1 cofactor is 1.
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev (P + 1) / 4. P ≡ 3 (mod 4), so a^SQRT_EXP is a square root of a when
    ///      a is a quadratic residue.
    uint256 internal constant SQRT_EXP =
        5472060717959818805561601436314318772174077789324455915672259473661306552146;

    /// @dev Curve constant b for E/Fp: y² = x³ + 3.
    uint256 internal constant B = 3;

    /// @dev Curve constant b' for the twist E'/Fp2: y² = x³ + 3/(9 + u).
    uint256 internal constant B2_C0 =
        19485874751759354771024239261021720505790618469301721065564631296452457478373;
    uint256 internal constant B2_C1 =
        266929791119991161246907387137283842545076965332900288569378510910307636690;

    /// @dev Bit length of R, minus one: the index of its most significant bit.
    uint256 private constant R_MSB = 253;

    // ------------------------------------------------------------- generators

    uint256 internal constant G1_X = 1;
    uint256 internal constant G1_Y = 2;

    uint256 internal constant G2_X_C0 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant G2_X_C1 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant G2_Y_C0 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 internal constant G2_Y_C1 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;

    // ------------------------------------------------- domain separation tag

    /// @dev Domain separation tag for hash-to-curve. Any off-chain signer MUST
    ///      use this exact tag and the exact procedure in `hashToG1`, or
    ///      signatures will not verify.
    bytes internal constant DST = "SORTITION-BLS-BN254-KECCAK-TAI-G1-v1";

    /// @dev Upper bound on hash-to-curve attempts. Each attempt succeeds with
    ///      probability ≈ 1/2, so exhausting this bound has probability ≈ 2^-256.
    uint256 private constant MAX_H2C_ITERATIONS = 256;

    // ------------------------------------------------------------------ types

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    /// @dev Fp2 elements are written a = c0 + c1·u with u² = −1. Note that this
    ///      is NOT the order the precompiles expect; `_encodeG2` handles the
    ///      swap to EIP-197's (imaginary, real) layout.
    struct G2Point {
        uint256 x_c0;
        uint256 x_c1;
        uint256 y_c0;
        uint256 y_c1;
    }

    /// @dev Jacobian coordinates over Fp2: affine (X/Z², Y/Z³). Z = 0 is infinity.
    struct G2Jac {
        uint256 x_c0;
        uint256 x_c1;
        uint256 y_c0;
        uint256 y_c1;
        uint256 z_c0;
        uint256 z_c1;
    }

    // ----------------------------------------------------------------- errors

    error CoordinateNotReduced();
    error PointNotOnCurve();
    error PointNotInSubgroup();
    error PointIsInfinity();
    error HashToCurveFailed();
    error ModexpFailed();
    error PairingFailed();

    // =====================================================================
    //                          public entry point
    // =====================================================================

    /// @notice Verify a BLS signature. Reverts if any input is malformed.
    /// @dev Performs full validation of both points, including the G2 subgroup
    ///      check, before touching `ecpairing`. That subgroup check dominates the
    ///      cost of this function — see the note on `verifyPrevalidatedKey` if the
    ///      public key has already been validated once and recorded.
    /// @param pubkey    Public key in G2.
    /// @param message   Message that was signed.
    /// @param signature Signature in G1.
    /// @return True if the signature is valid for this key and message.
    function verify(G2Point memory pubkey, bytes memory message, G1Point memory signature)
        internal
        view
        returns (bool)
    {
        validateG1(signature);
        validateG2(pubkey);
        return _verifyUnchecked(pubkey, message, signature);
    }

    /// @notice Verify a BLS signature whose public key has ALREADY been validated
    ///         by `validateG2` and stored somewhere trusted.
    /// @dev Skips only the G2 subgroup check, which is the expensive part. The
    ///      signature is still fully validated on every call. Passing an
    ///      unvalidated key here is a caller error: `ecpairing` on Arc was measured
    ///      to reject wrong-subgroup G2 points, so the call would revert rather
    ///      than verify — but do not rely on that, validate the key once and record it.
    function verifyPrevalidatedKey(G2Point memory pubkey, bytes memory message, G1Point memory signature)
        internal
        view
        returns (bool)
    {
        validateG1(signature);
        validateG2OnCurve(pubkey);
        return _verifyUnchecked(pubkey, message, signature);
    }

    function _verifyUnchecked(G2Point memory pubkey, bytes memory message, G1Point memory signature)
        private
        view
        returns (bool)
    {
        G1Point memory h = hashToG1(message);
        return pairingCheck2(signature, generatorG2(), negate(h), pubkey);
    }

    // =====================================================================
    //                            hash to curve
    // =====================================================================

    /// @notice Map a message to a point in G1 by try-and-increment.
    ///
    /// @dev CHOICE AND ITS COST — read this before depending on it.
    ///
    ///      This is try-and-increment (also called hash-and-check): keccak the
    ///      message to a field element x, and while x³ + 3 is not a quadratic
    ///      residue, increment x. Each attempt costs one `modexp` call.
    ///
    ///      Why this and not RFC 9380:
    ///        - The G1 cofactor is 1, so there is no cofactor clearing to do.
    ///          A point on the curve is in the subgroup, which removes the main
    ///          reason to prefer a structured map here.
    ///        - alt_bn128 has j-invariant 0 and A = 0, so simplified SWU does not
    ///          apply directly; RFC 9380 would require SVDW or a 3-isogeny map,
    ///          both materially more code and more constants to get right.
    ///        - This is a verification path. Correctness of a small, auditable
    ///          routine was weighted above the properties below.
    ///
    ///      What it costs, stated honestly:
    ///
    ///        NOT CONSTANT TIME. The number of iterations depends on the message.
    ///        Gas consumption is therefore message-dependent and publicly visible.
    ///        Here that leaks nothing, because every input to this function is
    ///        already public on chain — the message is public and there is no
    ///        secret being hashed. If this routine is ever reused somewhere the
    ///        input is secret, it is the wrong routine.
    ///
    ///        NOT INDIFFERENTIABLE from a random oracle to G1. RFC 9380 §10.5
    ///        discourages try-and-increment for exactly this reason. The output
    ///        distribution is close to, but not, uniform over G1. The BLS
    ///        unforgeability proof models H as a random oracle onto G1; this map
    ///        approximates that rather than achieving it.
    ///
    ///        UNBOUNDED IN THE WORST CASE, bounded in practice. Each iteration
    ///        succeeds with probability ≈ 1/2, so the expected count is 2 and the
    ///        loop is capped at 256 attempts, past which it reverts rather than
    ///        returning something unverified.
    ///
    ///      The canonical root is the numerically smaller of y and P − y, so the
    ///      map is deterministic. An off-chain signer must reproduce this exactly.
    function hashToG1(bytes memory message) internal view returns (G1Point memory) {
        uint256 x = uint256(keccak256(abi.encodePacked(DST, message))) % P;

        for (uint256 i = 0; i < MAX_H2C_ITERATIONS; ++i) {
            uint256 y2 = addmod(mulmod(mulmod(x, x, P), x, P), B, P);
            uint256 y = _modexp(y2, SQRT_EXP, P);

            if (mulmod(y, y, P) == y2) {
                // y == 0 would be a point of order 2. E(Fp) has odd prime order R,
                // so no such point exists; reject rather than return it if the
                // impossible happens.
                if (y == 0) {
                    x = addmod(x, 1, P);
                    continue;
                }
                uint256 negY = P - y;
                return G1Point(x, y < negY ? y : negY);
            }
            x = addmod(x, 1, P);
        }
        revert HashToCurveFailed();
    }

    // =====================================================================
    //                              validation
    // =====================================================================

    /// @notice Fully validate a G1 point. Reverts on anything suspect.
    /// @dev The G1 cofactor is 1 — E(Fp) has order exactly R — so a point on the
    ///      curve is necessarily in the correct subgroup and no scalar
    ///      multiplication is needed here. This was verified empirically, not
    ///      taken on faith; see the cofactor check in the stage-1 notes.
    function validateG1(G1Point memory p) internal pure {
        if (p.x >= P || p.y >= P) revert CoordinateNotReduced();
        if (p.x == 0 && p.y == 0) revert PointIsInfinity();
        if (!isOnCurveG1(p)) revert PointNotOnCurve();
    }

    /// @notice y² == x³ + 3 over Fp.
    function isOnCurveG1(G1Point memory p) internal pure returns (bool) {
        uint256 lhs = mulmod(p.y, p.y, P);
        uint256 rhs = addmod(mulmod(mulmod(p.x, p.x, P), p.x, P), B, P);
        return lhs == rhs;
    }

    /// @notice Fully validate a G2 point: reduced, not infinity, on curve, and in
    ///         the R-order subgroup.
    /// @dev The subgroup check is a full [R]P computation. The G2 cofactor is
    ///      large, so unlike G1 an on-curve point is NOT necessarily in the
    ///      subgroup — this check is load-bearing and cannot be skipped.
    function validateG2(G2Point memory p) internal pure {
        validateG2OnCurve(p);
        if (!isInSubgroupG2(p)) revert PointNotInSubgroup();
    }

    /// @notice The cheap half of G2 validation: reduced, not infinity, on curve.
    function validateG2OnCurve(G2Point memory p) internal pure {
        if (p.x_c0 >= P || p.x_c1 >= P || p.y_c0 >= P || p.y_c1 >= P) revert CoordinateNotReduced();
        if (p.x_c0 == 0 && p.x_c1 == 0 && p.y_c0 == 0 && p.y_c1 == 0) revert PointIsInfinity();
        if (!isOnCurveG2(p)) revert PointNotOnCurve();
    }

    /// @notice y² == x³ + b' over Fp2.
    function isOnCurveG2(G2Point memory p) internal pure returns (bool) {
        (uint256 l0, uint256 l1) = _fp2Sqr(p.y_c0, p.y_c1);

        (uint256 x2c0, uint256 x2c1) = _fp2Sqr(p.x_c0, p.x_c1);
        (uint256 r0, uint256 r1) = _fp2Mul(x2c0, x2c1, p.x_c0, p.x_c1);
        r0 = addmod(r0, B2_C0, P);
        r1 = addmod(r1, B2_C1, P);

        return l0 == r0 && l1 == r1;
    }

    /// @notice Is this on-curve G2 point in the R-order subgroup? True iff [R]P = O.
    /// @dev Deliberately the straightforward double-and-add rather than the
    ///      endomorphism-based shortcut (ψ(P) == [6u²]P). The shortcut is roughly
    ///      an order of magnitude cheaper but depends on a curve identity that is
    ///      easy to get subtly wrong and whose failure mode is silent acceptance of
    ///      an invalid key. Correctness was weighted above gas. If this cost
    ///      becomes the binding constraint, the shortcut is the documented upgrade
    ///      path and must land with its own differential test against this function.
    function isInSubgroupG2(G2Point memory p) internal pure returns (bool) {
        G2Jac memory acc; // all-zero == point at infinity

        for (uint256 i = R_MSB + 1; i > 0; --i) {
            _jacDouble(acc);
            if ((R >> (i - 1)) & 1 == 1) {
                _jacAddAffine(acc, p);
            }
        }
        return acc.z_c0 == 0 && acc.z_c1 == 0;
    }

    // =====================================================================
    //                              pairing
    // =====================================================================

    /// @notice Check e(a1, a2) · e(b1, b2) == 1 via the `ecpairing` precompile.
    /// @dev Two pairs, so 45,000 + 2·34,000 = 113,000 gas by the schedule measured
    ///      in gate/README.md. Reverts if the precompile rejects the input.
    function pairingCheck2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2)
        internal
        view
        returns (bool)
    {
        uint256[12] memory input;
        input[0] = a1.x;
        input[1] = a1.y;
        (input[2], input[3], input[4], input[5]) = _encodeG2(a2);
        input[6] = b1.x;
        input[7] = b1.y;
        (input[8], input[9], input[10], input[11]) = _encodeG2(b2);

        uint256[1] memory out;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x08, input, 384, out, 32)
        }
        if (!ok) revert PairingFailed();
        return out[0] == 1;
    }

    /// @dev EIP-197 orders each Fp2 coordinate as (imaginary, real).
    function _encodeG2(G2Point memory p) private pure returns (uint256, uint256, uint256, uint256) {
        return (p.x_c1, p.x_c0, p.y_c1, p.y_c0);
    }

    // =====================================================================
    //                              helpers
    // =====================================================================

    /// @notice −P for a G1 point. Assumes `p` is already validated.
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.x == 0 && p.y == 0) return G1Point(0, 0);
        return G1Point(p.x, P - p.y);
    }

    function generatorG1() internal pure returns (G1Point memory) {
        return G1Point(G1_X, G1_Y);
    }

    function generatorG2() internal pure returns (G2Point memory) {
        return G2Point(G2_X_C0, G2_X_C1, G2_Y_C0, G2_Y_C1);
    }

    /// @dev base^exp mod modulus via the `0x05` precompile. Measured present and
    ///      correct on Arc; see gate/tools/probe_edges.py.
    function _modexp(uint256 base, uint256 exp, uint256 modulus) private view returns (uint256 result) {
        uint256[6] memory input;
        input[0] = 32;
        input[1] = 32;
        input[2] = 32;
        input[3] = base;
        input[4] = exp;
        input[5] = modulus;

        uint256[1] memory out;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x05, input, 192, out, 32)
        }
        if (!ok) revert ModexpFailed();
        result = out[0];
    }

    // ------------------------------------------------------------ Fp2 arithmetic
    // Elements are c0 + c1·u with u² = −1.

    function _fp2Mul(uint256 a0, uint256 a1, uint256 b0, uint256 b1)
        private
        pure
        returns (uint256 c0, uint256 c1)
    {
        uint256 t0 = mulmod(a0, b0, P);
        uint256 t1 = mulmod(a1, b1, P);
        c0 = addmod(t0, P - t1, P);
        c1 = addmod(mulmod(a0, b1, P), mulmod(a1, b0, P), P);
    }

    function _fp2Sqr(uint256 a0, uint256 a1) private pure returns (uint256 c0, uint256 c1) {
        // (a0 + a1·u)² = (a0 + a1)(a0 − a1) + 2·a0·a1·u
        uint256 s = addmod(a0, a1, P);
        uint256 d = addmod(a0, P - a1, P);
        c0 = mulmod(s, d, P);
        uint256 m = mulmod(a0, a1, P);
        c1 = addmod(m, m, P);
    }

    function _fp2Add(uint256 a0, uint256 a1, uint256 b0, uint256 b1)
        private
        pure
        returns (uint256, uint256)
    {
        return (addmod(a0, b0, P), addmod(a1, b1, P));
    }

    function _fp2Sub(uint256 a0, uint256 a1, uint256 b0, uint256 b1)
        private
        pure
        returns (uint256, uint256)
    {
        return (addmod(a0, P - b0, P), addmod(a1, P - b1, P));
    }

    function _fp2MulSmall(uint256 a0, uint256 a1, uint256 k) private pure returns (uint256, uint256) {
        return (mulmod(a0, k, P), mulmod(a1, k, P));
    }

    // ------------------------------------------------------- G2 Jacobian arithmetic
    // Curve is y² = x³ + b' with a = 0, so the a=0 formulas apply.

    /// @dev dbl-2009-l, in place.
    function _jacDouble(G2Jac memory q) private pure {
        if (q.z_c0 == 0 && q.z_c1 == 0) return; // infinity doubles to infinity

        (uint256 a0, uint256 a1) = _fp2Sqr(q.x_c0, q.x_c1); // A = X²
        (uint256 b0, uint256 b1) = _fp2Sqr(q.y_c0, q.y_c1); // B = Y²
        (uint256 c0, uint256 c1) = _fp2Sqr(b0, b1); // C = B²

        // D = 2·((X + B)² − A − C)
        (uint256 d0, uint256 d1) = _fp2Add(q.x_c0, q.x_c1, b0, b1);
        (d0, d1) = _fp2Sqr(d0, d1);
        (d0, d1) = _fp2Sub(d0, d1, a0, a1);
        (d0, d1) = _fp2Sub(d0, d1, c0, c1);
        (d0, d1) = _fp2MulSmall(d0, d1, 2);

        // E = 3A,  F = E²
        (uint256 e0, uint256 e1) = _fp2MulSmall(a0, a1, 3);
        (uint256 f0, uint256 f1) = _fp2Sqr(e0, e1);

        // Z3 = 2·Y·Z   (before Y is overwritten)
        (uint256 z0, uint256 z1) = _fp2Mul(q.y_c0, q.y_c1, q.z_c0, q.z_c1);
        (z0, z1) = _fp2MulSmall(z0, z1, 2);

        // X3 = F − 2D
        (uint256 t0, uint256 t1) = _fp2MulSmall(d0, d1, 2);
        (uint256 x3_0, uint256 x3_1) = _fp2Sub(f0, f1, t0, t1);

        // Y3 = E·(D − X3) − 8C
        (t0, t1) = _fp2Sub(d0, d1, x3_0, x3_1);
        (t0, t1) = _fp2Mul(e0, e1, t0, t1);
        (uint256 c8_0, uint256 c8_1) = _fp2MulSmall(c0, c1, 8);
        (uint256 y3_0, uint256 y3_1) = _fp2Sub(t0, t1, c8_0, c8_1);

        q.x_c0 = x3_0;
        q.x_c1 = x3_1;
        q.y_c0 = y3_0;
        q.y_c1 = y3_1;
        q.z_c0 = z0;
        q.z_c1 = z1;
    }

    /// @dev madd-2007-bl: accumulator (Jacobian) += affine point, in place.
    function _jacAddAffine(G2Jac memory q, G2Point memory a) private pure {
        if (q.z_c0 == 0 && q.z_c1 == 0) {
            q.x_c0 = a.x_c0;
            q.x_c1 = a.x_c1;
            q.y_c0 = a.y_c0;
            q.y_c1 = a.y_c1;
            q.z_c0 = 1;
            q.z_c1 = 0;
            return;
        }

        (uint256 zz0, uint256 zz1) = _fp2Sqr(q.z_c0, q.z_c1); // Z1Z1
        (uint256 u2_0, uint256 u2_1) = _fp2Mul(a.x_c0, a.x_c1, zz0, zz1); // U2 = X2·Z1Z1

        // S2 = Y2·Z1·Z1Z1
        (uint256 s2_0, uint256 s2_1) = _fp2Mul(q.z_c0, q.z_c1, zz0, zz1);
        (s2_0, s2_1) = _fp2Mul(a.y_c0, a.y_c1, s2_0, s2_1);

        (uint256 h0, uint256 h1) = _fp2Sub(u2_0, u2_1, q.x_c0, q.x_c1); // H = U2 − X1
        (uint256 r0, uint256 r1) = _fp2Sub(s2_0, s2_1, q.y_c0, q.y_c1); // S2 − Y1

        if (h0 == 0 && h1 == 0) {
            if (r0 == 0 && r1 == 0) {
                _jacDouble(q); // same point
            } else {
                q.x_c0 = 0; // P + (−P) = O
                q.x_c1 = 0;
                q.y_c0 = 0;
                q.y_c1 = 0;
                q.z_c0 = 0;
                q.z_c1 = 0;
            }
            return;
        }

        (r0, r1) = _fp2MulSmall(r0, r1, 2); // r = 2·(S2 − Y1)

        (uint256 hh0, uint256 hh1) = _fp2Sqr(h0, h1); // HH
        (uint256 i0, uint256 i1) = _fp2MulSmall(hh0, hh1, 4); // I = 4·HH
        (uint256 j0, uint256 j1) = _fp2Mul(h0, h1, i0, i1); // J = H·I
        (uint256 v0, uint256 v1) = _fp2Mul(q.x_c0, q.x_c1, i0, i1); // V = X1·I

        // X3 = r² − J − 2V
        (uint256 x3_0, uint256 x3_1) = _fp2Sqr(r0, r1);
        (x3_0, x3_1) = _fp2Sub(x3_0, x3_1, j0, j1);
        (uint256 t0, uint256 t1) = _fp2MulSmall(v0, v1, 2);
        (x3_0, x3_1) = _fp2Sub(x3_0, x3_1, t0, t1);

        // Y3 = r·(V − X3) − 2·Y1·J
        (t0, t1) = _fp2Sub(v0, v1, x3_0, x3_1);
        (t0, t1) = _fp2Mul(r0, r1, t0, t1);
        (uint256 yj0, uint256 yj1) = _fp2Mul(q.y_c0, q.y_c1, j0, j1);
        (yj0, yj1) = _fp2MulSmall(yj0, yj1, 2);
        (uint256 y3_0, uint256 y3_1) = _fp2Sub(t0, t1, yj0, yj1);

        // Z3 = (Z1 + H)² − Z1Z1 − HH
        (uint256 z3_0, uint256 z3_1) = _fp2Add(q.z_c0, q.z_c1, h0, h1);
        (z3_0, z3_1) = _fp2Sqr(z3_0, z3_1);
        (z3_0, z3_1) = _fp2Sub(z3_0, z3_1, zz0, zz1);
        (z3_0, z3_1) = _fp2Sub(z3_0, z3_1, hh0, hh1);

        q.x_c0 = x3_0;
        q.x_c1 = x3_1;
        q.y_c0 = y3_0;
        q.y_c1 = y3_1;
        q.z_c0 = z3_0;
        q.z_c1 = z3_1;
    }
}
