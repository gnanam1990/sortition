#!/usr/bin/env python3
"""Measure precompile behaviour that gate/README.md did NOT establish.

Facts src/BN254.sol needs and must not assume:
  1. Does 0x05 (modexp) exist and work? The hash-to-curve needs a modular sqrt.
  2. Does 0x08 reject an off-curve G1 point?
  3. Does 0x08 reject an off-curve G2 point?
  4. Does 0x08 reject an on-curve G2 point in the WRONG subgroup?
  5. Does 0x08 reject a field element >= p?
  6. How does 0x08 treat the point at infinity, encoded (0,0)?

Read-only. Nothing is mined.
"""
import json, subprocess, sys

RPC = sys.argv[1] if len(sys.argv) > 1 else "https://rpc.testnet.arc.network"
LABEL = sys.argv[2] if len(sys.argv) > 2 else "ARC TESTNET"

sys.path.insert(0, "")
from py_ecc.optimized_bn128 import (G1, G2, curve_order, field_modulus, b2,
                                    multiply, normalize, is_on_curve, add, neg)
from py_ecc.optimized_bn128 import FQ2

P = field_modulus
R = curve_order


def w(x):
    return f"{int(x):064x}"


def call(addr, data):
    """Returns (ok, hexstring_or_error)."""
    req = json.dumps({"to": addr, "data": "0x" + data})
    pr = subprocess.run(["cast", "rpc", "eth_call", req, "latest", "--rpc-url", RPC],
                        capture_output=True, text=True)
    if pr.returncode != 0:
        return False, pr.stderr.strip().split("\n")[0][:140]
    return True, pr.stdout.strip().strip('"')


# ---------------------------------------------------------------- G1 / G2 data
g1x, g1y = 1, 2
n1 = normalize(neg(G1))
ng1x, ng1y = int(n1[0]), int(n1[1])

g2 = normalize(G2)
# EIP-197 order: x_imag, x_real, y_imag, y_real
G2ENC = w(g2[0].coeffs[1]) + w(g2[0].coeffs[0]) + w(g2[1].coeffs[1]) + w(g2[1].coeffs[0])


def find_wrong_subgroup_g2():
    """An on-curve point of E'(Fp2) that is NOT in the r-order subgroup."""
    for k in range(1, 400):
        x = FQ2([k, 1])
        y2 = x ** 3 + b2
        # sqrt in Fp2 via exponentiation: (p^2+1)/4  (p^2 == 3 mod 4)
        y = y2 ** ((P * P + 1) // 4)
        if y ** 2 != y2:
            continue
        pt = (x, y, FQ2.one())
        if not is_on_curve(pt, b2):
            continue
        if normalize(multiply(pt, R))[0] != FQ2.zero() or True:
            # [r]P != O  =>  not in the r-order subgroup
            rp = multiply(pt, R)
            if rp[2] != FQ2.zero():
                return normalize(pt)
    return None


print(f"=================== PRECOMPILE EDGE PROBE — {LABEL}")
print(f"    {RPC}\n")

# ------------------------------------------------- 1. modexp 0x05
print("--- 0x05 modexp — needed for the sqrt in hash-to-curve")
# known vector: 3^2 mod 100 = 9
d = w(1) + w(1) + w(1) + "03" + "02" + "64"
ok, out = call("0x0000000000000000000000000000000000000005", d)
print(f"  3^2 mod 100 : ok={ok} out={out}  expected 0x09  -> "
      f"{'CORRECT' if ok and out.endswith('09') and len(out) == 4 else 'CHECK'}")

# real vector: sqrt(4) = 4^((p+1)/4) mod p, must square back to 4
e = (P + 1) // 4
d = w(32) + w(32) + w(32) + w(4) + w(e) + w(P)
ok, out = call("0x0000000000000000000000000000000000000005", d)
root = int(out, 16) if ok else None
print(f"  4^((p+1)/4) mod p = {hex(root) if root is not None else 'FAIL'}")
print(f"  squares back to 4 : {'YES — modular sqrt works' if root is not None and pow(root,2,P)==4 else 'NO'}")
print()

# ------------------------------------------------- 0x08 edge cases
PAIR = "0x0000000000000000000000000000000000000008"


def pairing_case(name, data, note=""):
    ok, out = call(PAIR, data)
    if ok:
        v = int(out, 16) if out and out != "0x" else None
        print(f"  {name:<44} ACCEPTED, returned {v}   {note}")
    else:
        print(f"  {name:<44} REJECTED ({out.split(':')[-1].strip()[:60]})   {note}")
    return ok


print("--- 0x08 ecpairing input validation")

# valid control: e(G1,G2)*e(-G1,G2) == 1
pairing_case("valid 2-pair control (expect ACCEPTED, 1)",
             w(g1x) + w(g1y) + G2ENC + w(ng1x) + w(ng1y) + G2ENC)

# G1 off curve: (1,3) -> 9 != 1+3
pairing_case("G1 off-curve (1,3)",
             w(1) + w(3) + G2ENC + w(ng1x) + w(ng1y) + G2ENC)

# G1 coordinate >= p
pairing_case("G1 coordinate >= p",
             w(P) + w(2) + G2ENC + w(ng1x) + w(ng1y) + G2ENC)

# G2 off curve: perturb y_real
bad_g2 = w(g2[0].coeffs[1]) + w(g2[0].coeffs[0]) + w(g2[1].coeffs[1]) + w(int(g2[1].coeffs[0]) ^ 1)
pairing_case("G2 off-curve (y perturbed by one bit)",
             w(g1x) + w(g1y) + bad_g2 + w(ng1x) + w(ng1y) + G2ENC)

# G2 on curve, wrong subgroup
wsg = find_wrong_subgroup_g2()
if wsg is None:
    print("  wrong-subgroup G2                            COULD NOT CONSTRUCT")
else:
    onc = is_on_curve((wsg[0], wsg[1], FQ2.one()), b2)
    rp = multiply((wsg[0], wsg[1], FQ2.one()), R)
    in_sub = (rp[2] == FQ2.zero())
    print(f"  [constructed G2 point: on_curve={onc}, in_r_subgroup={in_sub}]")
    ws = w(wsg[0].coeffs[1]) + w(wsg[0].coeffs[0]) + w(wsg[1].coeffs[1]) + w(wsg[1].coeffs[0])
    pairing_case("G2 ON-curve but WRONG subgroup", w(g1x) + w(g1y) + ws,
                 "<< decides if we must check it ourselves")

# point at infinity
pairing_case("G1 = (0,0) infinity, valid G2", w(0) + w(0) + G2ENC)
pairing_case("G1 valid, G2 = all zeros (infinity)", w(g1x) + w(g1y) + w(0) * 4)
print()
print("--- empty input (identity case, should be 1)")
pairing_case("zero-length input", "")
