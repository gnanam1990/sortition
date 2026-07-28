#!/usr/bin/env python3
"""sortition operator daemon.

Watches RandomnessRequested, reconstructs the seed and message exactly as the
contract does, signs with the operator BLS key, and submits fulfillRandomness.

Run:
    python daemon/operator_daemon.py --rpc <url> --coordinator 0x... [--once]

Key material comes from the environment, never from a file in this repository.
See daemon/README.md for where the key should live and what happens if the host
is compromised.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web3 import Web3
from web3.exceptions import TransactionNotFound

import protocol

# ---------------------------------------------------------------- constants

# Arc-specific. The recorded failure modes these guard against are, in order:
# public RPC rate limiting, mempool saturation under load, and generic provider
# throttling. None of them are fatal; all of them are transient.
RETRYABLE_SUBSTRINGS = (
    "request limit reached",   # -32011, Arc public RPC hard limit
    "-32011",
    "txpool is full",          # -32003, mempool saturated
    "-32003",
    "rpc cooling",             # Arc-side rate limit, confirmed by Circle staff
    "429",
    "too many requests",
    "timeout",
    "connection",
    "temporarily unavailable",
)

# "already known" and "nonce too low" mean the network already has our work.
# Not errors, and specifically not something to retry into.
ALREADY_SUBMITTED_SUBSTRINGS = ("already known", "nonce too low", "replacement transaction underpriced")

BACKOFF_BASE = 0.5
BACKOFF_MAX = 30.0
MAX_ATTEMPTS = 6

# Base priority fee in wei before the Arc >100k-gas rule is applied.
DEFAULT_PRIORITY_WEI = 1_000_000_000  # 1 gwei

# Deadline reporting thresholds, as a fraction of REQUEST_TIMEOUT_BLOCKS.
WARN_FRACTION = 0.5
AT_RISK_FRACTION = 0.2


def log(level: str, msg: str, **kw):
    parts = " ".join(f"{k}={v}" for k, v in kw.items())
    print(f"[{time.strftime('%H:%M:%S')}] {level:<7} {msg} {parts}".rstrip(), flush=True)


# ---------------------------------------------------------------- state


@dataclass
class InFlight:
    request_id: int
    tx_hash: str
    nonce: int
    submitted_block: int
    sig_x: int
    sig_y: int


@dataclass
class State:
    """Persisted across restarts. Written BEFORE a transaction is sent, so a
    crash between signing and sending still leaves a record to reconcile."""
    last_scanned_block: int = 0
    inflight: dict = field(default_factory=dict)   # str(request_id) -> InFlight dict

    @classmethod
    def load(cls, path: Path) -> "State":
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text())
        return cls(last_scanned_block=raw.get("last_scanned_block", 0),
                   inflight=raw.get("inflight", {}))

    def save(self, path: Path):
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"last_scanned_block": self.last_scanned_block,
                                   "inflight": self.inflight}, indent=2))
        tmp.replace(path)   # atomic


# ---------------------------------------------------------------- daemon


class OperatorDaemon:
    def __init__(self, w3: Web3, coordinator, bls_sk: int, tx_key: str,
                 state_path: Path, priority_wei: int = DEFAULT_PRIORITY_WEI):
        self.w3 = w3
        self.c = coordinator
        self.bls_sk = bls_sk
        self.account = w3.eth.account.from_key(tx_key)
        self.state_path = state_path
        self.state = State.load(state_path)
        self.priority_wei = priority_wei

        self.chain_id = w3.eth.chain_id
        self.timeout_blocks = self.c.functions.REQUEST_TIMEOUT_BLOCKS().call()
        self.stats = {"fulfilled": 0, "skipped": 0, "missed": 0, "resubmitted": 0}
        # Request ids already observed in a settled state, so each is only
        # counted as skipped once even though the window is rescanned each poll.
        self.seen_settled: set[int] = set()

        # Fail fast if the registered key is not ours: every signature we produce
        # would be rejected, and that is better learned at startup than at the
        # first request.
        onchain = self.c.functions.operatorPubkey().call()
        ours = protocol.public_key(self.bls_sk)
        if tuple(onchain) != ours:
            raise SystemExit(
                "FATAL: the coordinator's registered public key does not match this "
                "BLS secret key. Every signature this daemon produced would be rejected."
            )
        log("INFO", "operator key matches the coordinator's registered key")

    # ------------------------------------------------------------ fees

    def fee_params(self, gas_estimate: int) -> dict:
        """Arc fee rules.

        The base fee is fetched immediately before every submission and NEVER
        cached — a stale base fee gets the transaction rejected or stuck, and
        this is the single highest-value operational rule on Arc gas.

        Above ~100,000 gas the priority fee is collapsed by 1e9. A normal-sized
        priority fee multiplied across a large gas amount pushes the total past
        maxGasLimit and the transaction fails. Every fulfilment is >100k gas, so
        this path is the normal one, not the exception.
        """
        base = self.w3.eth.get_block("latest")["baseFeePerGas"]
        prio = self.priority_wei
        if gas_estimate > 100_000:
            prio = max(1, prio // 10**9)
        return {"maxFeePerGas": base + prio, "maxPriorityFeePerGas": prio}

    # ------------------------------------------------------------ retry

    def with_retry(self, what: str, fn):
        """Retry transient RPC failures with exponential backoff and jitter.

        Rate limiting and a full mempool are expected operating conditions on
        Arc's public RPC, not crashes.
        """
        for attempt in range(MAX_ATTEMPTS):
            try:
                return fn()
            except Exception as e:                      # noqa: BLE001
                text = str(e).lower()
                if any(s in text for s in ALREADY_SUBMITTED_SUBSTRINGS):
                    raise
                if not any(s in text for s in RETRYABLE_SUBSTRINGS):
                    raise
                if attempt == MAX_ATTEMPTS - 1:
                    log("ERROR", f"{what}: giving up after {MAX_ATTEMPTS} attempts", err=str(e)[:120])
                    raise
                delay = min(BACKOFF_MAX, BACKOFF_BASE * (2 ** attempt))
                delay *= 0.5 + random.random()          # jitter
                log("WARN", f"{what}: transient failure, backing off",
                    attempt=attempt + 1, sleep=f"{delay:.2f}s", err=str(e)[:80])
                time.sleep(delay)

    # ------------------------------------------------------------ discovery

    def scan_window(self) -> int:
        """How far back a restart must look.

        A request older than REQUEST_TIMEOUT_BLOCKS cannot be fulfilled, so
        history beyond that is irrelevant. Backfill is therefore bounded and
        cheap no matter how long the daemon was down — there is never a need to
        scan from genesis.
        """
        return self.timeout_blocks + 16

    def pending_requests(self) -> list[int]:
        """Request ids that are Pending on chain and still fulfillable.

        Events drive discovery; contract state is the authority. A request is
        only acted on if the contract itself still says Pending.
        """
        head = self.w3.eth.block_number
        start = max(0, head - self.scan_window())
        if self.state.last_scanned_block:
            start = min(start, max(0, self.state.last_scanned_block - 8))

        found = []
        # Small ranges: Arc's public RPC rate-limits eth_getLogs aggressively.
        CHUNK = 64
        frm = start
        while frm <= head:
            to = min(head, frm + CHUNK - 1)
            logs = self.with_retry(
                "get_logs",
                lambda f=frm, t=to: self.c.events.RandomnessRequested().get_logs(
                    from_block=f, to_block=t),
            )
            for ev in logs or []:
                found.append(int(ev["args"]["requestId"]))
            frm = to + 1

        self.state.last_scanned_block = head
        self.state.save(self.state_path)

        pending = []
        for rid in sorted(set(found)):
            st = self.status_of(rid)
            if st == 1:                        # Status.Pending
                pending.append(rid)
            elif rid not in self.seen_settled:
                # Fulfilled by someone else, or expired. Filtering here rather
                # than in process() saves the work, but it must still be VISIBLE:
                # a skip that never appears in the counters looks identical to a
                # request the daemon never noticed. Counted once per request id,
                # since the discovery window is rescanned every poll.
                self.seen_settled.add(rid)
                self.stats["skipped"] += 1
                log("INFO", "request already settled, skipping",
                    request_id=rid, status=st)
        return pending

    def status_of(self, request_id: int) -> int:
        r = self.with_retry("requests", lambda: self.c.functions.requests(request_id).call())
        return int(r[3])

    def request_block(self, request_id: int) -> int:
        r = self.with_retry("requests", lambda: self.c.functions.requests(request_id).call())
        return int(r[1])

    # ------------------------------------------------------------ deadlines

    def deadline_report(self, request_id: int, req_block: int) -> tuple[str, int]:
        head = self.w3.eth.block_number
        deadline = req_block + self.timeout_blocks
        left = deadline - head
        if left <= 0:
            return "MISSED", left
        if left <= self.timeout_blocks * AT_RISK_FRACTION:
            return "AT_RISK", left
        if left <= self.timeout_blocks * WARN_FRACTION:
            return "WARN", left
        return "OK", left

    # ------------------------------------------------------------ signing

    def build_signature(self, request_id: int):
        """Reconstruct the seed and message exactly as the contract does, sign.

        The seed and message are computed locally rather than read from the
        contract, because that is what the daemon must be able to do. They are
        cross-checked against the contract's own view in the test suite.
        """
        req = self.with_retry("requests", lambda: self.c.functions.requests(request_id).call())
        requester, req_block = req[0], int(req[1])

        sb = protocol.seed_block(req_block)
        head = self.w3.eth.block_number
        if head <= sb:
            return None, req_block, "seed block not yet mined"

        blk = self.with_retry("get_block", lambda: self.w3.eth.get_block(sb))
        bh = bytes(blk["hash"])
        if bh == b"\x00" * 32:
            return None, req_block, "block hash unavailable"

        s = protocol.seed(request_id, requester, bh)
        msg = protocol.fulfilment_message(self.chain_id, self.c.address, request_id, s)
        sig = protocol.sign(self.bls_sk, msg)
        return sig, req_block, None

    # ------------------------------------------------------------ submission

    def submit(self, request_id: int, sig) -> str:
        fn = self.c.functions.fulfillRandomness(request_id, (sig[0], sig[1]))

        gas = self.with_retry("estimate_gas",
                              lambda: fn.estimate_gas({"from": self.account.address}))
        gas = int(gas * 12 // 10)

        nonce = self.w3.eth.get_transaction_count(self.account.address, "pending")
        tx = fn.build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": gas,
            "chainId": self.chain_id,
            **self.fee_params(gas),
        })
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.to_hex(self.w3.keccak(signed.raw_transaction))

        # WRITE AHEAD. The record exists before the transaction does, so a crash
        # between here and the next line still leaves something to reconcile.
        self.state.inflight[str(request_id)] = asdict(InFlight(
            request_id=request_id, tx_hash=tx_hash, nonce=nonce,
            submitted_block=self.w3.eth.block_number, sig_x=sig[0], sig_y=sig[1]))
        self.state.save(self.state_path)

        try:
            self.with_retry("send_raw_transaction",
                            lambda: self.w3.eth.send_raw_transaction(signed.raw_transaction))
        except Exception as e:                          # noqa: BLE001
            if any(s in str(e).lower() for s in ALREADY_SUBMITTED_SUBSTRINGS):
                log("INFO", "transaction already in the network", request_id=request_id)
            else:
                raise
        return tx_hash

    # ------------------------------------------------------------ reconcile

    def reconcile_inflight(self):
        """Resolve transactions that were submitted but whose receipt was never seen.

        This is the crash-in-the-middle case. The contract is asked first, because
        it is the only authority on whether the work is done — the receipt might
        be missing because we died, because the transaction was dropped from the
        mempool, or because someone else fulfilled the request first.

        Re-signing is safe: BLS is deterministic, so a resubmission carries the
        byte-identical signature. The worst case is two transactions landing, and
        the second reverts with RequestNotPending — wasted gas, never a corrupted
        record or a second callback.
        """
        for rid_s, rec in list(self.state.inflight.items()):
            rid = int(rid_s)
            status = self.status_of(rid)

            if status == 2:
                log("INFO", "in-flight request already fulfilled on chain, clearing",
                    request_id=rid)
                del self.state.inflight[rid_s]
                continue
            if status in (0, 3):
                log("WARN", "in-flight request is gone or expired, clearing",
                    request_id=rid, status=status)
                del self.state.inflight[rid_s]
                continue

            # Still Pending. Did our transaction land?
            try:
                rcpt = self.w3.eth.get_transaction_receipt(rec["tx_hash"])
                if rcpt["status"] == 1:
                    log("WARN", "receipt succeeded but request still pending; clearing",
                        request_id=rid)
                else:
                    log("WARN", "previous submission reverted; will retry", request_id=rid)
                del self.state.inflight[rid_s]
            except TransactionNotFound:
                age = self.w3.eth.block_number - rec["submitted_block"]
                if age < 4:
                    log("INFO", "submission still in flight, waiting",
                        request_id=rid, blocks=age)
                else:
                    log("WARN", "submission never landed; will resubmit",
                        request_id=rid, blocks=age)
                    del self.state.inflight[rid_s]
                    self.stats["resubmitted"] += 1
        self.state.save(self.state_path)

    # ------------------------------------------------------------ main

    def process(self, request_id: int):
        status = self.status_of(request_id)
        if status != 1:
            # Someone else fulfilled it, or it expired. Skipping is correct;
            # submitting anyway would revert and waste gas.
            log("INFO", "request no longer pending, skipping",
                request_id=request_id, status=status)
            self.stats["skipped"] += 1
            return

        if str(request_id) in self.state.inflight:
            return  # reconcile_inflight owns it

        sig, req_block, why = self.build_signature(request_id)
        level, left = self.deadline_report(request_id, req_block)

        if sig is None:
            log("INFO", f"not ready: {why}", request_id=request_id, blocks_left=left)
            return

        if level == "MISSED":
            # The one thing this design counts against the operator. Never let it
            # happen quietly.
            log("ERROR", "MISS: deadline passed before submission",
                request_id=request_id, blocks_left=left)
            self.stats["missed"] += 1
            return
        if level in ("WARN", "AT_RISK"):
            log("WARN", f"{level}: approaching deadline",
                request_id=request_id, blocks_left=left,
                seconds_left=f"{left * 0.5335:.0f}")

        tx = self.submit(request_id, sig)
        log("INFO", "submitted", request_id=request_id, tx=tx[:18], blocks_left=left)
        self.stats["fulfilled"] += 1

    def poll_once(self):
        self.reconcile_inflight()
        for rid in self.pending_requests():
            try:
                self.process(rid)
            except Exception as e:                      # noqa: BLE001
                log("ERROR", "processing failed", request_id=rid, err=str(e)[:160])

    def run(self, interval: float = 1.0, once: bool = False):
        log("INFO", "daemon starting", coordinator=self.c.address,
            chain=self.chain_id, timeout_blocks=self.timeout_blocks,
            fulfiller=self.account.address)
        while True:
            try:
                self.poll_once()
            except Exception as e:                      # noqa: BLE001
                log("ERROR", "poll failed", err=str(e)[:160])
            if once:
                return
            time.sleep(interval)


# ---------------------------------------------------------------- wiring


def load_abi(name: str):
    root = Path(__file__).resolve().parent.parent
    art = root / "out" / f"{name}.sol" / f"{name}.json"
    return json.loads(art.read_text())["abi"]


def load_bls_key(args) -> int:
    """Where the operator BLS secret comes from.

    Never a file in this repository, and never a default. See daemon/README.md.
    """
    if args.insecure_test_key is not None:
        log("WARN", "USING AN INSECURE TEST KEY — never do this against a real deployment")
        return int(args.insecure_test_key, 0)

    env = os.environ.get("SORTITION_BLS_SECRET")
    if env:
        return int(env, 0)

    path = os.environ.get("SORTITION_BLS_KEYFILE")
    if path:
        p = Path(path).expanduser()
        mode = p.stat().st_mode & 0o777
        if mode & 0o077:
            raise SystemExit(f"FATAL: {p} is readable by others (mode {mode:o}); chmod 600 it")
        return int(p.read_text().strip(), 0)

    raise SystemExit(
        "FATAL: no operator key. Set SORTITION_BLS_SECRET or SORTITION_BLS_KEYFILE.\n"
        "       See daemon/README.md before choosing where the key lives."
    )


def main(argv=None):
    ap = argparse.ArgumentParser(description="sortition operator daemon")
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--coordinator", required=True)
    ap.add_argument("--state", default=os.environ.get("SORTITION_STATE", "./sortition-state.json"))
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--once", action="store_true", help="single poll, then exit")
    ap.add_argument("--insecure-test-key", default=None,
                    help="TEST ONLY. Obvious in the process list on purpose.")
    ap.add_argument("--tx-key", default=os.environ.get("SORTITION_TX_KEY"),
                    help="key that pays gas; separate from the BLS key")
    args = ap.parse_args(argv)

    if not args.tx_key:
        raise SystemExit("FATAL: no transaction key. Set SORTITION_TX_KEY or pass --tx-key.")

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    coordinator = w3.eth.contract(
        address=Web3.to_checksum_address(args.coordinator), abi=load_abi("VRFCoordinator"))

    d = OperatorDaemon(w3, coordinator, load_bls_key(args), args.tx_key, Path(args.state))
    d.run(interval=args.interval, once=args.once)


if __name__ == "__main__":
    main()
