#!/usr/bin/env python3
"""Daemon tests against a local chain. Spawns and tears down its own anvil.

Run:  .venv/bin/python daemon/test_daemon.py

No deployment to Arc happens here or anywhere in this file.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from web3 import Web3                                    # noqa: E402
import protocol                                          # noqa: E402
from operator_daemon import OperatorDaemon, load_abi      # noqa: E402

PORT = 8549
RPC = f"http://127.0.0.1:{PORT}"

# Anvil's first well-known default account — published in Foundry's docs and
# printed on every start. Local chain only.
ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_KEY2 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

# The same TEST-ONLY BLS scalar as test/Vectors.sol. Controls nothing.
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
TEST_SK = 0x2A1F5B3C9D8E7F60415263748596A7B8C9D0E1F2031425364758697A8B9C0D1E % R

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{('  — ' + detail) if detail else ''}")


def sh(*args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def deploy(what, *ctor):
    cmd = ["forge", "create", what, "--rpc-url", RPC, "--private-key", ANVIL_KEY, "--broadcast"]
    if ctor:
        cmd += ["--constructor-args", *ctor]
    out = sh(*cmd, cwd=str(ROOT))
    for line in out.stdout.splitlines():
        if "Deployed to:" in line:
            return line.split()[-1]
    raise RuntimeError(f"deploy failed: {out.stdout}\n{out.stderr}")


def mine(w3, n=1):
    for _ in range(n):
        w3.provider.make_request("anvil_mine", [1])


def main():
    anvil = subprocess.Popen(["anvil", "--silent", "--port", str(PORT)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(3)
        w3 = Web3(Web3.HTTPProvider(RPC))
        assert w3.is_connected(), "anvil not reachable"

        pk = protocol.public_key(TEST_SK)
        coord_addr = deploy("src/VRFCoordinator.sol:VRFCoordinator",
                            f"({pk[0]},{pk[1]},{pk[2]},{pk[3]})")
        cons_addr = deploy("test/VRFCoordinator.t.sol:GoodConsumer")
        print(f"coordinator {coord_addr}\nconsumer    {cons_addr}\n")

        coord = w3.eth.contract(address=Web3.to_checksum_address(coord_addr),
                                abi=load_abi("VRFCoordinator"))
        cons = w3.eth.contract(address=Web3.to_checksum_address(cons_addr),
                               abi=json.loads((ROOT / "out" / "VRFCoordinator.t.sol"
                                               / "GoodConsumer.json").read_text())["abi"])
        acct = w3.eth.account.from_key(ANVIL_KEY)

        def make_request():
            tx = cons.functions.request(coord.address, 100_000).build_transaction({
                "from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address),
                "gas": 300_000, "chainId": w3.eth.chain_id})
            s = acct.sign_transaction(tx)
            h = w3.eth.send_raw_transaction(s.raw_transaction)
            w3.eth.wait_for_transaction_receipt(h)
            rid = coord.functions.nextRequestId().call() - 1
            mine(w3, 3)
            return rid

        def new_daemon(tag):
            st = Path(tempfile.mkdtemp()) / f"state-{tag}.json"
            return OperatorDaemon(w3, coord, TEST_SK, ANVIL_KEY, st), st

        # =============================================================
        print("--- 1. message construction must not drift from the contract")
        rid = make_request()
        req = coord.functions.requests(rid).call()
        requester, req_block = req[0], int(req[1])
        bh = bytes(w3.eth.get_block(protocol.seed_block(req_block))["hash"])

        off_seed = protocol.seed(rid, requester, bh)
        on_seed = coord.functions.seedOf(rid).call()
        check("seed matches contract seedOf()", off_seed == bytes(on_seed),
              f"off={off_seed.hex()[:16]} on={bytes(on_seed).hex()[:16]}")

        off_msg = protocol.fulfilment_message(w3.eth.chain_id, coord.address, rid, off_seed)
        on_msg = bytes(coord.functions.fulfilmentMessage(rid).call())
        check("message byte-identical to fulfilmentMessage()", off_msg == on_msg,
              f"{len(off_msg)} vs {len(on_msg)} bytes")

        sig = protocol.sign(TEST_SK, off_msg)
        off_rand = protocol.randomness_from_signature(*sig)

        # =============================================================
        print("\n--- 2. a request gets fulfilled end to end")
        d, _ = new_daemon("e2e")
        d.poll_once()
        time.sleep(0.3)
        mine(w3)

        status = coord.functions.requests(rid).call()[3]
        check("request status is Fulfilled", status == 2, f"status={status}")
        on_rand = bytes(coord.functions.randomnessOf(rid).call())
        check("on-chain randomness equals keccak(signature)", on_rand == off_rand)
        check("consumer received the callback", cons.functions.callCount().call() >= 1)
        check("consumer got the same value", bytes(cons.functions.lastRandomness().call()) == on_rand)
        req_c, ful_c, exp_c = coord.functions.operatorStats().call()
        check("fulfilled counter incremented", ful_c == 1, f"requested={req_c} fulfilled={ful_c}")

        # =============================================================
        print("\n--- 3. a duplicate submission is handled, not retried into a revert")
        d2, _ = new_daemon("dup")
        d2.poll_once()                      # same request, already fulfilled
        check("second daemon skipped the fulfilled request", d2.stats["skipped"] >= 1,
              f"skipped={d2.stats['skipped']} fulfilled={d2.stats['fulfilled']}")
        check("no second callback delivered", cons.functions.callCount().call() == 1)
        _, ful_after, _ = coord.functions.operatorStats().call()
        check("fulfilled counter not double-counted", ful_after == 1)

        # Same daemon polling twice must also be a no-op.
        before = d.stats["fulfilled"]
        d.poll_once()
        check("repeat poll on the same daemon is a no-op",
              d.stats["fulfilled"] == before, f"fulfilled={d.stats['fulfilled']}")

        # =============================================================
        print("\n--- 4. a request fulfilled by someone else is skipped")
        rid2 = make_request()
        req2 = coord.functions.requests(rid2).call()
        bh2 = bytes(w3.eth.get_block(protocol.seed_block(int(req2[1])))["hash"])
        s2 = protocol.seed(rid2, req2[0], bh2)
        m2 = protocol.fulfilment_message(w3.eth.chain_id, coord.address, rid2, s2)
        sig2 = protocol.sign(TEST_SK, m2)

        # A third party relays it first. fulfillRandomness is permissionless:
        # the signature is the authorisation, not the sender.
        other = w3.eth.account.from_key(ANVIL_KEY2)
        tx = coord.functions.fulfillRandomness(rid2, (sig2[0], sig2[1])).build_transaction({
            "from": other.address, "nonce": w3.eth.get_transaction_count(other.address),
            "gas": 500_000, "chainId": w3.eth.chain_id})
        sgn = other.sign_transaction(tx)
        rc = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(sgn.raw_transaction))
        check("third party could fulfil (permissionless)", rc["status"] == 1)

        d3, _ = new_daemon("other")
        d3.poll_once()
        check("daemon skipped the externally-fulfilled request", d3.stats["skipped"] >= 1,
              f"skipped={d3.stats['skipped']} fulfilled={d3.stats['fulfilled']}")
        check("daemon submitted nothing", d3.stats["fulfilled"] == 0)

        # =============================================================
        print("\n--- 5. restart safety")
        rid3 = make_request()
        d4, state_path = new_daemon("restart")
        d4.poll_once()
        mine(w3)
        check("state file written", state_path.exists())

        # Simulate a crash after submission by replaying a stale in-flight record
        # against a request the chain has already fulfilled.
        d5, state5 = new_daemon("crash")
        d5.state.inflight[str(rid3)] = {
            "request_id": rid3, "tx_hash": "0x" + "11" * 32, "nonce": 0,
            "submitted_block": w3.eth.block_number, "sig_x": 1, "sig_y": 2}
        d5.state.save(state5)
        d5.reconcile_inflight()
        check("stale in-flight record cleared once the chain shows Fulfilled",
              str(rid3) not in d5.state.inflight)

        # A dropped transaction for a still-pending request must be resubmitted.
        rid4 = make_request()
        d6, state6 = new_daemon("dropped")
        d6.state.inflight[str(rid4)] = {
            "request_id": rid4, "tx_hash": "0x" + "22" * 32, "nonce": 0,
            "submitted_block": w3.eth.block_number - 10, "sig_x": 1, "sig_y": 2}
        d6.state.save(state6)
        d6.reconcile_inflight()
        check("dropped submission for a pending request is cleared for retry",
              str(rid4) not in d6.state.inflight and d6.stats["resubmitted"] == 1)
        d6.poll_once()
        mine(w3)
        check("the retry actually fulfilled it",
              coord.functions.requests(rid4).call()[3] == 2)

        # =============================================================
        print("\n--- 6. deadline awareness")
        rid5 = make_request()
        d7, _ = new_daemon("deadline")
        rb = coord.functions.requests(rid5).call()[1]
        lvl, left = d7.deadline_report(rid5, rb)
        check("fresh request reports OK", lvl == "OK", f"level={lvl} blocks_left={left}")

        mine(w3, 180)
        lvl, left = d7.deadline_report(rid5, rb)
        check("near-deadline request reports AT_RISK", lvl == "AT_RISK",
              f"level={lvl} blocks_left={left}")

        mine(w3, 30)
        lvl, left = d7.deadline_report(rid5, rb)
        check("past-deadline request reports MISSED", lvl == "MISSED",
              f"level={lvl} blocks_left={left}")
        d7.process(rid5)
        check("a miss is reported loudly, not silently", d7.stats["missed"] == 1)

        # =============================================================
        print("\n--- 7. key mismatch is fatal at startup, not at first request")
        try:
            OperatorDaemon(w3, coord, TEST_SK + 1, ANVIL_KEY,
                           Path(tempfile.mkdtemp()) / "s.json")
            check("wrong BLS key rejected at construction", False, "no error raised")
        except SystemExit as e:
            check("wrong BLS key rejected at construction", "does not match" in str(e))

    finally:
        anvil.terminate()
        try:
            anvil.wait(timeout=5)
        except subprocess.TimeoutExpired:
            anvil.kill()

    print(f"\n{'=' * 60}\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for f in FAILED:
            print(f"  FAILED: {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
