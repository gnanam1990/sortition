# BN254 precompile gate check — Arc testnet

This directory is the feasibility gate that the rest of the project depends on. It was run
**before** any design work, to answer one question: does Arc testnet support the standard
BN254 (alt_bn128) precompiles well enough for threshold BLS to be possible at all?

**Answer: yes.** All three precompiles are present, correct, and priced on the standard
EIP-1108 schedule.

## Result

Measured on **Arc testnet, chain ID 5042002, at block 54,049,634, on 2026-07-28.**

| Precompile | Present | Correct vs known vector | Gas |
|---|---|---|---|
| `0x06` ecadd | yes | yes | 150 |
| `0x07` ecmul | yes | yes | 6,000 |
| `0x08` ecpairing | yes | yes | 45,000 + 34,000·k |

A threshold-BLS verification is a two-pairing check — `e(σ, G2) · e(−H(m), pk) == 1` —
which costs **113,000 gas**. Including the 21,000 intrinsic cost and calldata, a full
verification transaction is roughly 138,000 gas.

Pricing was *derived, not assumed*: a 4-pair check cost 181,000 and a 2-pair check 113,000,
so the marginal cost is `(181000 − 113000) / 2 = 34,000` per pairing and the fixed base is
45,000. That is EIP-1108 (post-Istanbul) pricing, not the pre-1108 `100,000 + 80,000·k`.

Arc matched a stock EVM (anvil) on every single number.

## The negative vector, and why it is the important one

Three of the vectors are positive checks — they assert that a known input produces a known
output. The fourth is a **negative** check, and it is the one that carries the weight.

```
positive:  e(G1, G2) · e(−G1, G2) == 1   ->  precompile must return 1
negative:  e(G1, G2) · e( G1, G2) != 1   ->  precompile must return 0
```

A precompile that is stubbed out — one that ignores its input and returns a constant `1` —
**passes the positive check**. It looks like working pairing arithmetic. It fails only the
negative check.

Without the negative vector, "ecpairing works on Arc" would be an unfalsifiable claim.
Arc returns `0` for the negative vector, so the precompile is doing real pairing arithmetic
rather than faking a success path.

The same reasoning drove the choice of every vector here: each one has an answer that is
known independently of any chain, so a **wrong** result is distinguishable from a
**failure**. A precompile that is absent returns empty; a precompile that is broken returns
something that is not the published constant. These are different findings and the harness
tells them apart.

## Follow-up measurements (added during stage 1)

Building the BLS library needed facts the original gate did not cover. Rather than
assume them, they were measured the same way — read-only, on Arc testnet.
`tools/probe_edges.py` reproduces all of it.

**`0x05` modexp is present and correct.** `3^2 mod 100` returns 9, and
`4^((p+1)/4) mod p` returns a value that squares back to 4, so modular square
roots work. The hash-to-curve depends on this.

**`0x08` validates its inputs and fails closed.** Every malformed input was
rejected outright rather than silently accepted:

| Input to `ecpairing` | Result |
|---|---|
| Valid 2-pair control | accepted, returned 1 |
| G1 off-curve `(1,3)` | **rejected** |
| G1 coordinate ≥ p | **rejected** |
| G2 off-curve (one bit flipped in y) | **rejected** |
| G2 on-curve but in the **wrong subgroup** | **rejected** |
| G1 = `(0,0)` (infinity) with valid G2 | accepted, returned 1 |
| G2 = all zeros (infinity) | accepted, returned 1 |
| Zero-length input | accepted, returned 1 |

The wrong-subgroup row is the notable one, and it required constructing a genuine
point on the twist E'(Fp2) outside the R-order subgroup to test at all. Arc's
precompile rejects it.

That does **not** make the library's own subgroup check redundant. This is
measured behaviour of one chain on one day, not a specification Arc has committed
to. `src/BN254.sol` validates every point itself before calling any precompile and
treats this rejection as a backstop.

**The G1 cofactor is 1.** E(Fp) has order exactly R, so for G1 — and only G1 — a
point being on the curve implies it is in the correct subgroup. Verified across 40
on-curve points, each satisfying [R]P = O. G2 has a large cofactor and gets no such
shortcut.

## Contents

| Path | What it is |
|---|---|
| `src/BN254Gate.sol` | The probe contract. `BN254Gate` writes results to storage for read-back after a mined tx; `BN254GateProbe` runs the same probes in a constructor so results can be obtained via `eth_call` with no key and no mined transaction. |
| `tools/vectors.py` | Derives the test vectors, including the negative one. |
| `tools/probe.sh` | Raw `eth_call` probe straight at the precompile addresses — no contract involved. |
| `tools/decode_probe.py` | Decodes the constructor-probe payload and checks each result against its known answer. |
| `tools/readback.sh` | Reads all results back out of a deployed `BN254Gate`'s storage. |

## Reproducing

Nothing here needs a funded key or a deployed contract. Gas metering under `eth_call` is the
same EVM code path as in a mined transaction — `eth_call` skips state persistence and fee
payment, not gas accounting. This was verified rather than assumed: on anvil, the
constructor probe under `eth_call` returned 294 / 6,144 / 113,144 / 181,144, byte-identical
to the same contract's storage after a mined transaction. (Those figures each include 144
gas of `staticcall` overhead on top of the precompile's own cost.)

```bash
# 1. Raw precompile probe, no contract
./tools/probe.sh https://rpc.testnet.arc.network "ARC TESTNET"

# 2. In-contract gas measurement, still nothing mined
FOUNDRY_PROFILE=gate forge build
BC=$(jq -r '.bytecode.object' ../out-gate/BN254Gate.sol/BN254GateProbe.json)
OUT=$(cast call --rpc-url https://rpc.testnet.arc.network --create "$BC")
python3 tools/decode_probe.py "$OUT" "ARC TESTNET"
```

## What this gate did not establish

- **That Arc will accept and mine such a transaction.** Nothing was deployed. Arc has
  transaction-admission rules around `maxGasLimit` and priority fees that `eth_call`
  bypasses entirely. At 138,000 gas against a 30,000,000 block gas limit this is not
  expected to be a problem, but it is untested.
- **A stable USDC price for a verification.** At the base fee observed on the day
  (20 gwei) a verification cost ~0.0023 USDC, but the base fee moves and Arc's standing
  guidance is to re-read it before every transaction. Treat the **gas** figures as hard and
  the USDC figures as a snapshot.

For the record, the native/gas denomination on Arc was measured at 18 decimals (recent
transfers carry round values such as `1e17` = 0.1 USDC), while the ERC-20 face at
`0x3600…0000` returned `decimals() = 6` on the same day.
