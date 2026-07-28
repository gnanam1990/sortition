#!/usr/bin/env python3
"""Validate a candidate operator public key. Needs no secret and mines nothing.

    .venv/bin/python tools/validate_pubkey.py <x_c0> <x_c1> <y_c0> <y_c1> [--rpc URL]

Two independent checks, because this decides whether a deployment is even
possible and a wrong answer is expensive:

  1. py_ecc, locally — on the twist E'(Fp2), and [R]P == O.
  2. THE ACTUAL SOLIDITY the coordinator's constructor will run, executed on Arc
     via `eth_call --create`. Not a reimplementation of it, the same code.

If these two ever disagree, do not deploy.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "daemon"))

from py_ecc.optimized_bn128 import (                     # noqa: E402
    curve_order as R, field_modulus as P, b2, multiply, is_on_curve, FQ2,
)


def onchain_check(pk, rpc):
    art = json.loads((ROOT / "out" / "PubkeyProbe.sol" / "PubkeyProbe.json").read_text())
    bc = art["bytecode"]["object"]
    args = subprocess.run(
        ["cast", "abi-encode", "constructor((uint256,uint256,uint256,uint256))",
         f"({pk[0]},{pk[1]},{pk[2]},{pk[3]})"],
        capture_output=True, text=True, check=True).stdout.strip()
    data = bc + args.removeprefix("0x")
    out = subprocess.run(["cast", "call", "--rpc-url", rpc, "--create", data],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return None, out.stderr.strip()[:200]
    raw = out.stdout.strip().removeprefix("0x")
    w = [int(raw[i:i + 64], 16) for i in range(0, len(raw), 64)]
    return dict(zip(("reduced", "infinity", "onCurve", "inSubgroup", "accepted"), w)), None


def main():
    ap = argparse.ArgumentParser()
    # Accepts four separate arguments OR one quoted string, comma- or
    # space-separated. zsh does not word-split unquoted expansions the way bash
    # does, so "$PK" as a single argument is the common case, not a mistake.
    ap.add_argument("coords", nargs="+", help="x_c0 x_c1 y_c0 y_c1 (or one quoted string)")
    ap.add_argument("--rpc", default="https://rpc.testnet.arc.network")
    args = ap.parse_args()

    flat = []
    for chunk in args.coords:
        flat += [t for t in chunk.replace(",", " ").replace("(", " ").replace(")", " ").split() if t]
    if len(flat) != 4:
        raise SystemExit(f"expected 4 coordinates, got {len(flat)}: {flat}")
    pk = [int(c, 0) for c in flat]
    print("candidate public key")
    for name, v in zip(("x_c0", "x_c1", "y_c0", "y_c1"), pk):
        print(f"  {name} = {v}")
    print()

    # ---- 1. local
    reduced = all(0 <= v < P for v in pk)
    infinity = all(v == 0 for v in pk)
    on_curve = in_sub = False
    if reduced and not infinity:
        pt = (FQ2([pk[0], pk[1]]), FQ2([pk[2], pk[3]]), FQ2.one())
        on_curve = bool(is_on_curve(pt, b2))
        if on_curve:
            in_sub = multiply(pt, R)[2] == FQ2.zero()
    local_ok = reduced and not infinity and on_curve and in_sub

    print("1. local check (py_ecc)")
    print(f"   coordinates reduced (< p) : {reduced}")
    print(f"   not the point at infinity : {not infinity}")
    print(f"   on the twist E'(Fp2)      : {on_curve}")
    print(f"   in the R-order subgroup   : {in_sub}")
    print(f"   -> {'VALID' if local_ok else 'REJECTED'}")
    print()

    # ---- 2. on chain, using the real Solidity
    res, err = onchain_check(pk, args.rpc)
    print(f"2. on-chain check — src/BN254.sol executed on {args.rpc}")
    if err:
        print(f"   PROBE FAILED: {err}")
        chain_ok = None
    else:
        for k in ("reduced", "infinity", "onCurve", "inSubgroup"):
            print(f"   {k:<25} : {bool(res[k])}")
        chain_ok = bool(res["accepted"])
        print(f"   -> constructor would {'ACCEPT' if chain_ok else 'REVERT'}")
    print()

    if chain_ok is None:
        print("VERDICT: INCONCLUSIVE — the on-chain probe did not run. Do not deploy.")
        sys.exit(2)
    if local_ok != chain_ok:
        print("VERDICT: THE TWO CHECKS DISAGREE. DO NOT DEPLOY.")
        sys.exit(3)
    print(f"VERDICT: {'SAFE TO REGISTER' if local_ok else 'UNUSABLE — the constructor will revert'}")
    sys.exit(0 if local_ok else 1)


if __name__ == "__main__":
    main()
