#!/usr/bin/env python3
"""Verify a fulfilment on chain, WITHOUT trusting the coordinator's own verdict.

    .venv/bin/python tools/verify_onchain_fulfilment.py <coordinator> <requestId> <fulfilTxHash> [--rpc URL]

The coordinator says the signature verified. That is the coordinator's opinion. This
re-derives everything from raw chain data and checks it with py_ecc's pairing —
a different implementation from src/BN254.sol — so the conclusion does not depend
on the contract being correct.

Deliberately does NOT call seedOf() or fulfilmentMessage(). Those revert once the
seed's block hash ages out of the 256-block BLOCKHASH window, which is by design.
Everything here is rebuilt from eth_getBlockByNumber, which has no such window, so
this works for any past fulfilment however old.

Nothing is mined. No key is needed.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "daemon"))

import protocol                                                    # noqa: E402
from py_ecc.optimized_bn128 import G2, pairing, neg, FQ, FQ2, is_on_curve   # noqa: E402

FAIL = []


def check(label, cond, detail=""):
    if not cond:
        FAIL.append(label)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}{('  — ' + detail) if detail else ''}")


def cast(*args, rpc):
    time.sleep(1.5)   # Arc's public RPC rate-limits tight loops
    p = subprocess.run(["cast", *args, "--rpc-url", rpc], capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"cast {' '.join(args[:2])} failed: {p.stderr.strip()[:200]}")
    return p.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("coordinator")
    ap.add_argument("request_id", type=int)
    ap.add_argument("tx_hash")
    ap.add_argument("--rpc", default="https://rpc.testnet.arc.network")
    a = ap.parse_args()

    rid, coord, rpc = a.request_id, a.coordinator, a.rpc
    chain_id = int(cast("chain-id", rpc=rpc))
    print(f"chain {chain_id}  coordinator {coord}  request {rid}\n")

    # ---- request record
    req = cast("call", coord, "requests(uint256)(address,uint48,uint32,uint8)",
               str(rid), rpc=rpc).split()
    requester, req_block, status = req[0], int(req[1]), int(req[-1])
    print("--- request record")
    check("status is Fulfilled (2)", status == 2, f"status={status}")

    # ---- seed, rebuilt from the block hash rather than from seedOf()
    sb = protocol.seed_block(req_block)
    blk = json.loads(cast("rpc", "eth_getBlockByNumber", hex(sb), "false", rpc=rpc))
    bh = bytes.fromhex(blk["hash"].removeprefix("0x"))
    seed = protocol.seed(rid, requester, bh)
    msg = protocol.fulfilment_message(chain_id, coord, rid, seed)
    print("\n--- seed and message, rebuilt from chain data alone")
    print(f"  seed block {sb}  hash 0x{bh.hex()}")
    print(f"  seed       0x{seed.hex()}")
    print(f"  message    {len(msg)} bytes")

    # ---- signature from the fulfilment calldata
    data = cast("tx", a.tx_hash, "input", rpc=rpc).removeprefix("0x")
    sel = data[:8]
    sig_rid, sx, sy = int(data[8:72], 16), int(data[72:136], 16), int(data[136:200], 16)
    print("\n--- signature, from the fulfilment transaction's calldata")
    check("selector is fulfillRandomness", sel == "9502dcdf", f"0x{sel}")
    check("calldata request id matches", sig_rid == rid, f"{sig_rid}")

    pt = (FQ(sx), FQ(sy), FQ.one())
    check("signature is on y^2 = x^3 + 3", bool(is_on_curve(pt, FQ(3))),
          "G1 cofactor is 1, so on-curve is a complete subgroup check")

    # ---- randomness derivation
    rand = protocol.randomness_from_signature(sx, sy)
    onchain = cast("call", coord, "randomnessOf(uint256)(bytes32)", str(rid), rpc=rpc)
    print("\n--- randomness derivation")
    check("keccak(abi.encode(x,y)) == randomnessOf()",
          "0x" + rand.hex() == onchain, f"0x{rand.hex()}")

    # ---- the actual pairing check, independent of src/BN254.sol
    pk = [int(v) for v in cast("call", coord,
                               "operatorPubkey()((uint256,uint256,uint256,uint256))",
                               rpc=rpc).strip("()").replace(",", " ").split()
          if v.lstrip("-").isdigit()][:4]
    pk_pt = (FQ2([pk[0], pk[1]]), FQ2([pk[2], pk[3]]), FQ2.one())
    h = protocol.to_pt(protocol.hash_to_g1(msg))
    lhs, rhs = pairing(G2, pt), pairing(pk_pt, neg(h))
    print("\n--- BLS verification with py_ecc, NOT with src/BN254.sol")
    check("e(sig, G2) * e(-H(m), pubkey) == 1", lhs * rhs == lhs.one())

    print()
    if FAIL:
        print(f"FAILED: {len(FAIL)} check(s) — {', '.join(FAIL)}")
        sys.exit(1)
    print("VERDICT: the fulfilment is genuine, verified independently of the contract.")


if __name__ == "__main__":
    main()
