#!/usr/bin/env python3
"""Build known-good BN254 (alt_bn128) precompile test vectors.

Every vector here is one whose answer is known independently of any chain,
so a WRONG answer is distinguishable from a FAILURE.
"""

P = 21888242871839275222246405745257275088696311157297823662689037894645226208583

def w(x):
    return f"{x:064x}"

# G1 generator
G1x, G1y = 1, 2
# -G1
NG1x, NG1y = 1, P - 2

# G2 generator, EIP-197 encoding: (x_imag, x_real, y_imag, y_real)
G2x1 = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2  # imag
G2x0 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed  # real
G2y1 = 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b  # imag
G2y0 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa  # real

G2 = w(G2x1) + w(G2x0) + w(G2y1) + w(G2y0)

# ---- 0x06 ecadd: G1 + G1 = 2G1 -------------------------------------------
ECADD_IN = "0x" + w(G1x) + w(G1y) + w(G1x) + w(G1y)
# 2*G1 on alt_bn128, a universally published constant
TWOG_X = 0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3
TWOG_Y = 0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4
ECADD_EXPECT = "0x" + w(TWOG_X) + w(TWOG_Y)

# ---- 0x07 ecmul: G1 * 2 = 2G1 (must agree with ecadd above) --------------
ECMUL_IN = "0x" + w(G1x) + w(G1y) + w(2)
ECMUL_EXPECT = ECADD_EXPECT

# ---- 0x08 ecpairing ------------------------------------------------------
# POSITIVE: e(G1,G2) * e(-G1,G2) == 1  -> returns 1
PAIR_TRUE_IN = "0x" + w(G1x) + w(G1y) + G2 + w(NG1x) + w(NG1y) + G2
PAIR_TRUE_EXPECT = "0x" + w(1)

# NEGATIVE: e(G1,G2) * e(G1,G2) == e(G1,G2)^2 != 1 -> returns 0
# This is the control. A stub that always returns 1 fails HERE, not above.
PAIR_FALSE_IN = "0x" + w(G1x) + w(G1y) + G2 + w(G1x) + w(G1y) + G2
PAIR_FALSE_EXPECT = "0x" + w(0)

if __name__ == "__main__":
    import json, sys
    out = {
        "ecadd":      {"addr": "0x0000000000000000000000000000000000000006", "input": ECADD_IN,      "expect": ECADD_EXPECT},
        "ecmul":      {"addr": "0x0000000000000000000000000000000000000007", "input": ECMUL_IN,      "expect": ECMUL_EXPECT},
        "pair_true":  {"addr": "0x0000000000000000000000000000000000000008", "input": PAIR_TRUE_IN,  "expect": PAIR_TRUE_EXPECT},
        "pair_false": {"addr": "0x0000000000000000000000000000000000000008", "input": PAIR_FALSE_IN, "expect": PAIR_FALSE_EXPECT},
    }
    json.dump(out, sys.stdout, indent=2)
    print()
