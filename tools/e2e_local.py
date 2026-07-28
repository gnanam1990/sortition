#!/usr/bin/env python3
"""End-to-end fulfilment against a local anvil, for the true transaction gas.

The forge suite measures contract execution only. A real submission also pays the
21,000 intrinsic cost and calldata, which is what actually converts to USDC.

This also proves the OFF-CHAIN message construction matches the contract's
`fulfilmentMessage` exactly — the operator daemon in a later stage has to
reproduce it byte for byte, and this is the first place that is checked against a
live contract rather than against another copy of my own assumptions.

Usage:  .venv/bin/python tools/e2e_local.py <rpc> <coordinator> <consumer>
"""
import json, subprocess, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bls_reference import hash_to_g1, keccak256, P
from py_ecc.optimized_bn128 import multiply, normalize, FQ

RPC = sys.argv[1]
COORD = sys.argv[2]
# Anvil's first well-known default account. Published in Foundry's own docs and
# printed by anvil on every start. Local-chain only; it controls nothing anywhere
# else and must never be used against a public network.
ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Same TEST-ONLY BLS scalar as test/Vectors.sol. Not a wallet key: it holds no
# funds and authorises no transaction. A real operator key never appears here.
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
SK = 0x2A1F5B3C9D8E7F60415263748596A7B8C9D0E1F2031425364758697A8B9C0D1E % R


def cast(*args):
    pr = subprocess.run(["cast", *args, "--rpc-url", RPC], capture_output=True, text=True)
    if pr.returncode != 0:
        raise RuntimeError(pr.stderr.strip()[:300])
    return pr.stdout.strip()


def u256(x):
    return int(x).to_bytes(32, "big")


def main():
    consumer = sys.argv[3]
    chain_id = int(cast("chain-id"))

    # --- request
    out = cast("send", consumer, "request(address,uint32)", COORD, "100000",
               "--private-key", ANVIL_KEY, "--json")
    rec = json.loads(out)
    req_gas = int(rec["gasUsed"], 16)
    req_block = int(rec["blockNumber"], 16)

    request_id = int(cast("call", COORD, "nextRequestId()(uint256)").split()[0]) - 1
    print(f"requestId {request_id} recorded at block {req_block}, request tx gas {req_gas:,}")

    # --- advance so blockhash(req_block + 1) exists
    subprocess.run(["cast", "rpc", "anvil_mine", "3", "--rpc-url", RPC],
                   capture_output=True, text=True)

    # --- rebuild the seed off chain, exactly as the contract does
    seed_block = req_block + 1
    bh = json.loads(subprocess.run(
        ["cast", "rpc", "eth_getBlockByNumber", hex(seed_block), "false", "--rpc-url", RPC],
        capture_output=True, text=True).stdout)["hash"]
    bh_bytes = bytes.fromhex(bh.removeprefix("0x"))

    requester = cast("call", COORD, "requests(uint256)(address,uint48,uint32,uint8)",
                     str(request_id)).split()[0]

    # seed = keccak256(abi.encode(requestId, requester, blockhash))
    seed = keccak256(u256(request_id) + bytes(12) + bytes.fromhex(requester.removeprefix("0x")) + bh_bytes)

    onchain_seed = cast("call", COORD, "seedOf(uint256)(bytes32)", str(request_id))
    assert seed.hex() == onchain_seed.removeprefix("0x"), \
        f"SEED MISMATCH\n  offchain {seed.hex()}\n  onchain  {onchain_seed}"
    print(f"seed matches contract: 0x{seed.hex()}")

    # message = abi.encodePacked("sortition/v1/fulfil", chainid, address(this), id, seed)
    message = (b"sortition/v1/fulfil" + u256(chain_id)
               + bytes.fromhex(COORD.removeprefix("0x")) + u256(request_id) + seed)

    onchain_msg = cast("call", COORD, "fulfilmentMessage(uint256)(bytes)", str(request_id))
    assert message.hex() == onchain_msg.removeprefix("0x"), \
        f"MESSAGE MISMATCH\n  offchain {message.hex()}\n  onchain  {onchain_msg}"
    print(f"message matches contract ({len(message)} bytes)")

    # --- sign
    h = hash_to_g1(message)
    sig = normalize(multiply((FQ(h[0]), FQ(h[1]), FQ.one()), SK))
    sx, sy = int(sig[0]), int(sig[1])

    # --- fulfil
    out = cast("send", COORD, "fulfillRandomness(uint256,(uint256,uint256))",
               str(request_id), f"({sx},{sy})", "--private-key", ANVIL_KEY, "--json")
    rec = json.loads(out)
    status = int(rec["status"], 16)
    ful_gas = int(rec["gasUsed"], 16)
    assert status == 1, "fulfilment reverted"

    randomness = cast("call", COORD, "randomnessOf(uint256)(bytes32)", str(request_id))
    expect = keccak256(u256(sx) + u256(sy))
    assert randomness.removeprefix("0x") == expect.hex(), "randomness mismatch"

    delivered = cast("call", consumer, "lastRandomness()(bytes32)")
    calls = int(cast("call", consumer, "callCount()(uint256)").split()[0])

    print()
    print("=========== END-TO-END FULFILMENT (real transactions, local chain)")
    print(f"  status                     : {status} (success)")
    print(f"  randomness on chain        : {randomness}")
    print(f"  delivered to consumer      : {delivered}  (callCount {calls})")
    print(f"  matches keccak(sig)        : {randomness.removeprefix('0x') == expect.hex()}")
    print()
    print(f"  requestRandomness()  tx gas : {req_gas:,}")
    print(f"  fulfillRandomness()  tx gas : {ful_gas:,}   <-- full transaction, incl. 21k intrinsic + calldata")
    gp = 20_200_000_000
    print(f"  fulfilment at 20.2 gwei     : {ful_gas * gp / 1e18:.7f} USDC")
    print(f"  fulfilments per 30M block   : {30_000_000 // ful_gas}")


if __name__ == "__main__":
    main()
