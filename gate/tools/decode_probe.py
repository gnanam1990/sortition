#!/usr/bin/env python3
"""Decode the constructor-probe return payload (17 words)."""
import sys

TWOGX = 0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3
TWOGY = 0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4

raw = sys.argv[1].removeprefix("0x")
label = sys.argv[2] if len(sys.argv) > 2 else ""
w = [int(raw[i:i+64], 16) for i in range(0, len(raw), 64)]
assert len(w) == 17, f"expected 17 words, got {len(w)}"

(aOk, aGas, aX, aY, mOk, mGas, mX, mY,
 ptOk, ptGas, ptOut, pfOk, pfGas, pfOut, p4Ok, p4Gas, p4Out) = w

def yn(v): return "YES" if v else "NO"
def hx(v): return "0x" + f"{v:064x}"

print(f"=========== IN-CONTRACT PROBE: {label}")
print("--- 0x06 ecadd   G1 + G1 == 2*G1")
print(f"  staticcall succeeded = {yn(aOk)}")
print(f"  gas charged          = {aGas}   (incl. 144 gas call overhead -> precompile {aGas-144})")
print(f"  returned x = {hx(aX)}")
print(f"  expected x = {hx(TWOGX)}")
print(f"  returned y = {hx(aY)}")
print(f"  expected y = {hx(TWOGY)}")
print(f"  VERDICT = {'CORRECT' if (aX==TWOGX and aY==TWOGY) else 'WRONG'}")

print("\n--- 0x07 ecmul   G1 * 2 == 2*G1")
print(f"  staticcall succeeded = {yn(mOk)}")
print(f"  gas charged          = {mGas}   (incl. 144 overhead -> precompile {mGas-144})")
print(f"  returned x = {hx(mX)}")
print(f"  expected x = {hx(TWOGX)}")
print(f"  returned y = {hx(mY)}")
print(f"  expected y = {hx(TWOGY)}")
print(f"  VERDICT = {'CORRECT' if (mX==TWOGX and mY==TWOGY) else 'WRONG'}")

print("\n--- 0x08 ecpairing  2 pairs, e(G1,G2)*e(-G1,G2) == 1   (expect 1)")
print(f"  staticcall succeeded = {yn(ptOk)}   returned = {ptOut}   expected = 1")
print(f"  gas charged          = {ptGas}   (incl. 144 overhead -> precompile {ptGas-144})")
print(f"  VERDICT = {'CORRECT' if ptOut==1 else 'WRONG'}")

print("\n--- 0x08 ecpairing  2 pairs, e(G1,G2)^2 != 1   (expect 0)  << anti-stub control")
print(f"  staticcall succeeded = {yn(pfOk)}   returned = {pfOut}   expected = 0")
print(f"  gas charged          = {pfGas}")
print(f"  VERDICT = {'CORRECT' if pfOut==0 else 'WRONG — precompile is not really pairing'}")

print("\n--- 0x08 ecpairing  4 pairs, product == 1   (expect 1)")
print(f"  staticcall succeeded = {yn(p4Ok)}   returned = {p4Out}   expected = 1")
print(f"  gas charged          = {p4Gas}   (incl. 144 overhead -> precompile {p4Gas-144})")
print(f"  VERDICT = {'CORRECT' if p4Out==1 else 'WRONG'}")

per = (p4Gas - ptGas) // 2
base = ptGas - 144 - 2*per
print(f"\n  marginal gas per pairing = ({p4Gas} - {ptGas}) / 2 = {per}")
print(f"  implied fixed base       = {base}")
print(f"  => pricing model: {base} + {per} * k   "
      f"({'EIP-1108 (post-Istanbul)' if per==34000 else 'pre-EIP-1108' if per==80000 else 'NON-STANDARD'})")
