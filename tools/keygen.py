#!/usr/bin/env python3
"""Generate an operator BLS keypair. RUN THIS ON THE OPERATOR HOST, NOWHERE ELSE.

The secret it produces is the entire security of the service. Anyone holding it
can compute every future output before anyone else sees it. It must never be
pasted into a chat, committed, or generated on a machine you do not control.

    .venv/bin/python tools/keygen.py --out ~/.sortition/operator.key

Writes the secret to `--out` with mode 0600 and prints ONLY the public key.
The public key is what gets registered on chain and is safe to share.
"""
import argparse
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "daemon"))
import protocol                                            # noqa: E402
from py_ecc.optimized_bn128 import (                       # noqa: E402
    curve_order as R, b2, multiply, normalize, is_on_curve, FQ2,
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="path for the secret; must not be in this repo")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    out = Path(args.out).expanduser().resolve()
    repo = Path(__file__).resolve().parent.parent
    if repo in out.parents or out.parent == repo:
        raise SystemExit(f"REFUSING: {out} is inside the repository. Choose a path outside it.")
    if out.exists() and not args.force:
        raise SystemExit(f"REFUSING: {out} already exists. Overwriting would destroy a key.")

    # Uniform in [1, R-1] by rejection, so no modulo bias.
    while True:
        sk = int.from_bytes(secrets.token_bytes(32), "big")
        if 1 <= sk < R:
            break

    pk = protocol.public_key(sk)
    pt = (FQ2([pk[0], pk[1]]), FQ2([pk[2], pk[3]]), FQ2.one())

    # Never emit a key the coordinator's constructor would reject.
    assert is_on_curve(pt, b2), "generated public key is not on the twist"
    assert multiply(pt, R)[2] == FQ2.zero(), "generated public key is not in the R-order subgroup"

    # Round-trip: the key must actually sign something that verifies.
    msg = b"keygen self-test"
    sig = protocol.sign(sk, msg)
    assert sig[0] != 0 or sig[1] != 0, "self-test signature is degenerate"

    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(hex(sk) + "\n")
    os.chmod(out, 0o600)

    print(f"secret written to {out} (mode 0600). It is not printed here on purpose.")
    print()
    print("Public key — safe to share, this is what gets registered on chain:")
    print(f"  x_c0 = {pk[0]}")
    print(f"  x_c1 = {pk[1]}")
    print(f"  x_c0/x_c1/y_c0/y_c1 as constructor args:")
    print(f"  ({pk[0]},{pk[1]},{pk[2]},{pk[3]})")
    print()
    print("  y_c0 =", pk[2])
    print("  y_c1 =", pk[3])
    print()
    print("Checked locally: on the twist, and in the R-order subgroup.")
    print("Point the daemon at it with:  export SORTITION_BLS_KEYFILE=" + str(out))


if __name__ == "__main__":
    main()
