#!/usr/bin/env python3
"""Off-chain reference signer, used to generate test vectors.

This is a THIN LAYER over daemon/protocol.py, which owns the only Python
implementation of the hash-to-curve and message construction. Nothing
protocol-defining is reimplemented here — a second copy would be a place for the
on-chain and off-chain sides to drift apart silently.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "daemon"))

from protocol import (  # noqa: E402
    DST, B, P, keccak256, hash_to_g1, to_pt, sign as _sign,
)
from py_ecc.optimized_bn128 import (  # noqa: E402
    G1, G2, curve_order as R, multiply, normalize, neg, pairing, FQ, FQ2,
)


def sign(sk: int, message: bytes):
    """(x, y) of [sk]·H(m). Delegates to the canonical implementation."""
    return _sign(sk, message)


def pubkey(sk: int):
    """[sk]·G2 in normalized FQ2 form, for emitting Solidity literals."""
    return normalize(multiply(G2, sk))


def verify_offchain(pk, message: bytes, sig) -> bool:
    """e(sig, G2) * e(-H(m), pk) == 1, computed with py_ecc's own pairing.

    Deliberately independent of src/BN254.sol: the point of this function is to
    be a second opinion, not an echo.
    """
    h = to_pt(hash_to_g1(message))
    sig_pt = (FQ(int(sig[0])), FQ(int(sig[1])), FQ.one())
    pk_pt = (pk[0], pk[1], FQ2.one())
    lhs = pairing(G2, sig_pt)
    rhs = pairing(pk_pt, neg(h))
    return lhs * rhs == lhs.one()


if __name__ == "__main__":
    SK = 0x2A1F5B3C9D8E7F60415263748596A7B8C9D0E1F2031425364758697A8B9C0D1E % R
    MSG = b"sortition stage 1 known-good vector"
    pk = pubkey(SK)
    sig = sign(SK, MSG)
    print("reference signature verifies off-chain:", verify_offchain(pk, MSG, sig))
