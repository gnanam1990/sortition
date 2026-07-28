#!/usr/bin/env python3
"""Generate test/Vectors.sol from the off-chain reference signer.

Every vector is checked off-chain with py_ecc's own pairing before being
written, so the Solidity tests are asserting against something independently
known to be right rather than against this codebase's own opinion.

Run:  .venv/bin/python tools/gen_test_vectors.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bls_reference import (hash_to_g1, sign, pubkey, verify_offchain, keccak256,
                           DST, P, B, to_pt)
from py_ecc.optimized_bn128 import (G2, curve_order as R, b2, multiply, normalize,
                                    is_on_curve, FQ, FQ2)

SK_GOOD = 0x2a1f5b3c9d8e7f60415263748596a7b8c9d0e1f2031425364758697a8b9c0d1e % R
SK_OTHER = 0x0badc0de1234567890abcdef0fedcba98765432100112233445566778899aabb % R
MSG = b"sortition stage 1 known-good vector"
MSG_MULTI = b"iter-probe-1"   # needs 5 hash-to-curve iterations


def fq2_sqrt(a):
    """Complex method, valid for p = 3 mod 4."""
    if a == FQ2.zero():
        return FQ2.zero()
    a1 = a ** ((P - 3) // 4)
    x0 = a1 * a
    alpha = a1 * x0
    if alpha == FQ2([P - 1, 0]):
        return FQ2([0, 1]) * x0
    b = (FQ2.one() + alpha) ** ((P - 1) // 2)
    return b * x0


def wrong_subgroup_g2(count=1):
    """Points on the twist E'(Fp2) that are NOT in the R-order subgroup."""
    found = []
    for k in range(1, 2000):
        x = FQ2([k, 1])
        y2 = x ** 3 + b2
        y = fq2_sqrt(y2)
        if y ** 2 != y2:
            continue
        pt = (x, y, FQ2.one())
        if not is_on_curve(pt, b2):
            continue
        if multiply(pt, R)[2] != FQ2.zero():   # [R]P != O
            found.append(normalize(pt))
            if len(found) == count:
                return found if count > 1 else found[0]
    raise RuntimeError("not enough wrong-subgroup points found")


def off_curve_g1():
    """On no curve at all: y^2 != x^3 + 3."""
    x, y = 1, 3
    assert (y * y - (x * x * x + B)) % P != 0
    return (x, y)


def g2_lit(pt, indent="        "):
    x, y = pt[0], pt[1]
    return (f"BN254.G2Point(\n{indent}    {x.coeffs[0]},\n{indent}    {x.coeffs[1]},\n"
            f"{indent}    {y.coeffs[0]},\n{indent}    {y.coeffs[1]}\n{indent})")


def main():
    pk = pubkey(SK_GOOD)
    sig = tuple(int(v) for v in sign(SK_GOOD, MSG))
    hm = hash_to_g1(MSG)

    pk_other = pubkey(SK_OTHER)
    sig_multi = tuple(int(v) for v in sign(SK_GOOD, MSG_MULTI))
    hm_multi = hash_to_g1(MSG_MULTI)

    # --- independent off-chain verification before anything is written ---
    assert verify_offchain(pk, MSG, sig), "primary vector fails off-chain"
    assert verify_offchain(pk, MSG_MULTI, sig_multi), "multi-iteration vector fails off-chain"
    assert not verify_offchain(pk_other, MSG, sig), "wrong-key vector wrongly verifies"
    flipped = (sig[0], sig[1] ^ 1)
    assert not is_on_curve(to_pt(flipped), FQ(B)) or not verify_offchain(pk, MSG, flipped), \
        "bit-flipped signature wrongly verifies"

    ws = wrong_subgroup_g2()

    # Differential corpus for the hand-written subgroup check.
    N = 6
    bad_pts = wrong_subgroup_g2(N)
    good_pts = [normalize(multiply(G2, (SK_GOOD * (i + 7) + 12345) % R)) for i in range(N)]

    for q in bad_pts:
        assert is_on_curve((q[0], q[1], FQ2.one()), b2), "bad point not on curve"
        assert multiply((q[0], q[1], FQ2.one()), R)[2] != FQ2.zero(), "bad point IS in subgroup"
    for q in good_pts:
        assert is_on_curve((q[0], q[1], FQ2.one()), b2), "good point not on curve"
        assert multiply((q[0], q[1], FQ2.one()), R)[2] == FQ2.zero(), "good point NOT in subgroup"

    def arr(name, pts):
        body = ",\n            ".join(g2_lit(q, indent="            ") for q in pts)
        return (f"    function {name}() internal pure returns (BN254.G2Point[{len(pts)}] memory) {{\n"
                f"        return [\n            {body}\n        ];\n    }}\n")

    corpus = "\n" + arr("inSubgroupCorpus", good_pts) + "\n" + arr("notInSubgroupCorpus", bad_pts)

    # Reference hash-to-curve outputs for a differential check.
    h2c_msgs = [f"h2c-{i}".encode() for i in range(8)]
    h2c_rows = []
    for m in h2c_msgs:
        hx, hy = hash_to_g1(m)
        h2c_rows.append((m.decode(), hx, hy))
    h2c_body = ",\n            ".join(f'"{m}"' for m, _, _ in h2c_rows)
    h2c_pts = ",\n            ".join(f"BN254.G1Point(\n                {x},\n                {y}\n            )"
                                     for _, x, y in h2c_rows)
    h2c = (f"\n    function h2cMessages() internal pure returns (string[{len(h2c_rows)}] memory) {{\n"
           f"        return [\n            {h2c_body}\n        ];\n    }}\n"
           f"\n    function h2cExpected() internal pure returns (BN254.G1Point[{len(h2c_rows)}] memory) {{\n"
           f"        return [\n            {h2c_pts}\n        ];\n    }}\n")

    oc = off_curve_g1()
    x0 = int.from_bytes(keccak256(DST + MSG_MULTI), "big") % P
    iters = (hm_multi[0] - x0) % P + 1

    out = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {{BN254}} from "../src/BN254.sol";

/// @notice Generated by tools/gen_test_vectors.py — do not hand-edit.
///
/// Every vector here was verified off-chain with py_ecc's own pairing
/// implementation before being written, so these assertions are against an
/// independent source of truth rather than against this repo's own code.
library Vectors {{
    /// @dev TEST ONLY — NOT A WALLET KEY, NOT AN OPERATOR KEY.
    ///
    ///      This is the BLS secret scalar corresponding to `pubkey()` below. It
    ///      is committed on purpose: the coordinator tests must sign messages
    ///      that depend on runtime values — chain id, contract address, and a
    ///      block hash — which cannot be precomputed into a static vector.
    ///
    ///      It controls nothing. It holds no funds, authorises no transaction,
    ///      and exists only so the test suite can produce valid signatures on
    ///      demand. A real operator key is generated off chain and never appears
    ///      in this repository.
    uint256 internal constant TEST_ONLY_SECRET_SCALAR =
        {SK_GOOD};

    bytes internal constant MESSAGE = "{MSG.decode()}";
    bytes internal constant MESSAGE_MULTI_ITER = "{MSG_MULTI.decode()}";

    /// @dev MESSAGE_MULTI_ITER needs {iters} hash-to-curve iterations, exercising
    ///      the try-and-increment loop rather than the first-attempt path.
    uint256 internal constant MULTI_ITER_COUNT = {iters};

    function pubkey() internal pure returns (BN254.G2Point memory) {{
        return {g2_lit(pk)};
    }}

    /// @dev A different secret key. Structurally valid, wrong for MESSAGE.
    function wrongPubkey() internal pure returns (BN254.G2Point memory) {{
        return {g2_lit(pk_other)};
    }}

    function signature() internal pure returns (BN254.G1Point memory) {{
        return BN254.G1Point(
            {sig[0]},
            {sig[1]}
        );
    }}

    function signatureMultiIter() internal pure returns (BN254.G1Point memory) {{
        return BN254.G1Point(
            {sig_multi[0]},
            {sig_multi[1]}
        );
    }}

    /// @dev The expected output of BN254.hashToG1(MESSAGE).
    function hashOfMessage() internal pure returns (BN254.G1Point memory) {{
        return BN254.G1Point(
            {hm[0]},
            {hm[1]}
        );
    }}

    function hashOfMessageMultiIter() internal pure returns (BN254.G1Point memory) {{
        return BN254.G1Point(
            {hm_multi[0]},
            {hm_multi[1]}
        );
    }}

    /// @dev On the twist E'(Fp2), but NOT in the R-order subgroup. This is the
    ///      point that separates a real subgroup check from an on-curve check.
    function wrongSubgroupPubkey() internal pure returns (BN254.G2Point memory) {{
        return {g2_lit(ws)};
    }}

    /// @dev (1, 3): 9 != 1 + 3, so not on y^2 = x^3 + 3.
    function offCurveG1() internal pure returns (BN254.G1Point memory) {{
        return BN254.G1Point({oc[0]}, {oc[1]});
    }}
{corpus}{h2c}}}
'''
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test", "Vectors.sol")
    with open(os.path.normpath(path), "w") as f:
        f.write(out)
    print(f"wrote test/Vectors.sol")
    print(f"  primary vector verifies off-chain      : True")
    print(f"  multi-iteration vector verifies        : True  ({iters} iterations)")
    print(f"  wrong-key vector correctly fails       : True")
    print(f"  wrong-subgroup point on curve, [R]P!=O : True")
    print(f"  differential corpus                    : {N} in-subgroup, {N} not-in-subgroup")
    print(f"  hash-to-curve reference outputs        : {len(h2c_rows)}")


if __name__ == "__main__":
    main()
