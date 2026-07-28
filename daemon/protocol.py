#!/usr/bin/env python3
"""Canonical off-chain implementation of the sortition protocol.

THIS IS THE ONLY PYTHON IMPLEMENTATION OF THE HASH-TO-CURVE AND MESSAGE
CONSTRUCTION. Everything else — the daemon, the test-vector generator, the
end-to-end harness — imports from here. A second copy anywhere would be a place
for the two to drift, and drift here is the worst kind of bug this system can
have: the signatures would be perfectly valid over the wrong message, so they
would verify against nothing and the daemon would look broken rather than wrong.

Every construction below mirrors a specific piece of src/BN254.sol or
src/VRFCoordinator.sol. `daemon/test_daemon.py` asserts the match against a live
contract, so if either side is edited without the other, the tests fail.
"""
from Crypto.Hash import keccak
from py_ecc.optimized_bn128 import (
    G1, G2, field_modulus as P, curve_order as R,
    multiply, normalize, FQ, FQ2,
)

# Mirrors BN254.DST
DST = b"SORTITION-BLS-BN254-KECCAK-TAI-G1-v1"
# Mirrors BN254.B
B = 3
# Mirrors the literal in VRFCoordinator.fulfilmentMessage
FULFIL_TAG = b"sortition/v1/fulfil"
MAX_H2C_ITERATIONS = 256


def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def u256(x: int) -> bytes:
    return int(x).to_bytes(32, "big")


def addr_bytes(a: str) -> bytes:
    return bytes.fromhex(a.removeprefix("0x"))


# ---------------------------------------------------------------- hash to curve

def hash_to_g1(message: bytes):
    """Try-and-increment. Mirrors BN254.hashToG1 exactly.

    Not constant time — the iteration count depends on the message. That is
    acceptable here for the same reason it is on chain: every input is public.
    The canonical root is the numerically smaller of y and P - y.
    """
    x = int.from_bytes(keccak256(DST + message), "big") % P
    for _ in range(MAX_H2C_ITERATIONS):
        y2 = (pow(x, 3, P) + B) % P
        y = pow(y2, (P + 1) // 4, P)
        if (y * y) % P == y2 and y != 0:
            return (x, min(y, P - y))
        x = (x + 1) % P
    raise RuntimeError("hash to curve failed")


def to_pt(xy):
    return (FQ(xy[0]), FQ(xy[1]), FQ.one())


# ---------------------------------------------------------------- BLS

def sign(sk: int, message: bytes):
    """Signature = [sk]·H(m) in G1. Deterministic: one valid signature exists."""
    sig = normalize(multiply(to_pt(hash_to_g1(message)), sk))
    return (int(sig[0]), int(sig[1]))


def public_key(sk: int):
    """Public key = [sk]·G2. Returns (x_c0, x_c1, y_c0, y_c1)."""
    pk = normalize(multiply(G2, sk))
    return (int(pk[0].coeffs[0]), int(pk[0].coeffs[1]),
            int(pk[1].coeffs[0]), int(pk[1].coeffs[1]))


# ---------------------------------------------------------------- coordinator

def seed(request_id: int, requester: str, block_hash: bytes) -> bytes:
    """Mirrors VRFCoordinator.seedOf:
    keccak256(abi.encode(requestId, requester, blockhash(requestBlock + 1)))
    """
    assert len(block_hash) == 32, "block hash must be 32 bytes"
    return keccak256(u256(request_id) + bytes(12) + addr_bytes(requester) + block_hash)


def fulfilment_message(chain_id: int, coordinator: str, request_id: int, seed_: bytes) -> bytes:
    """Mirrors VRFCoordinator.fulfilmentMessage:
    abi.encodePacked("sortition/v1/fulfil", chainid, address(this), requestId, seed)
    """
    return (FULFIL_TAG + u256(chain_id) + addr_bytes(coordinator)
            + u256(request_id) + seed_)


def randomness_from_signature(sig_x: int, sig_y: int) -> bytes:
    """Mirrors VRFCoordinator: keccak256(abi.encode(signature.x, signature.y))."""
    return keccak256(u256(sig_x) + u256(sig_y))


def seed_block(request_block: int) -> int:
    """The block whose hash feeds the seed."""
    return request_block + 1
