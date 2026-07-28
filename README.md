# sortition

**This is a single-operator service.** One operator runs it. Because BLS signatures are
deterministic, there is exactly one valid output for any given input, and the operator
cannot choose, bias, grind or reroll it — any output that verifies is the only output that
could have verified. What the operator *can* do is decline to publish an output at all. That
is the real trust assumption, and it is not hidden: a request is recorded on chain when it is
made, so a request that is never answered is visible on chain to anyone looking. The operator
cannot pick the number; the operator can refuse to give you one, and you can see that they
did.

Everything below follows from that sentence. Read it before using this for anything.

## What this is

A verifiable randomness service for Arc, built on threshold BLS. Arc has no VRF and no
randomness contract — this is an attempt to provide one whose output can be checked on chain
rather than trusted.

The name is the classical term for selection by lot.

## Status

**Deployed to Arc testnet. Unaudited. Do not use this for anything that matters.** Being
deployed changes nothing about that warning — the library, the coordinator and the operator
daemon are tested, but none of it has been reviewed by anyone other than its author.

### Deployed

| Contract | Address |
|---|---|
| `VRFCoordinator` | `0x17376aA831C70998F37522f00FD9f26d44977052` |
| `ExampleConsumer` | `0x493297D2ca32D279e7E7dc08D691C0BB01Ca833e` |

Arc testnet, chain **5042002**, block **54,075,709**. One full request has been made and
fulfilled on chain. Addresses, transaction hashes, measured gas and the read-backs that
prove it are in [`docs/addresses.md`](docs/addresses.md), along with what that single
fulfilment does *not* demonstrate.

- [x] Feasibility gate — BN254 precompiles verified on Arc testnet (see [`gate/`](gate/))
- [x] PRD — [`docs/PRD.md`](docs/PRD.md)
- [x] BLS verification library — [`src/BN254.sol`](src/BN254.sol)
- [x] Coordinator — [`src/VRFCoordinator.sol`](src/VRFCoordinator.sol)
- [x] Operator daemon — [`daemon/`](daemon/)
- [x] Testnet deployment — [`docs/addresses.md`](docs/addresses.md)
- [ ] Audit

## The feasibility gate

Threshold BLS needs the standard BN254 precompiles. Arc runs its own precompile set and EVM
equivalence could not be assumed, so this was checked against chain before any design work.

All three precompiles — `0x06` ecadd, `0x07` ecmul, `0x08` ecpairing — are present, return
correct results for known-good vectors, and are priced on the standard EIP-1108 schedule.
A two-pairing verification costs **113,000 gas**. Measured at block 54,049,634 on
2026-07-28.

The check includes a negative vector: a pairing that must return `0`. A stubbed precompile
that always returns `1` passes every positive check and fails that one. Full detail and
reproduction steps in [`gate/README.md`](gate/README.md).

## Verifying a fulfilment yourself

You do not have to trust this repository's own BLS library to check that an output is
genuine:

```bash
.venv/bin/python tools/verify_onchain_fulfilment.py <coordinator> <requestId> <fulfilTxHash>
```

It re-derives the seed, the signed message and the signature from raw chain data and checks
the pairing with **py_ecc — a different implementation from `src/BN254.sol`**. If the
coordinator and an independent pairing library disagree, that script says so.

## What this does not claim

- It is not trust-minimised across multiple parties. There is one operator.
- Liveness is not guaranteed. Suppression is detectable, not preventable.
- Nothing has been audited. It is deployed to testnet only, and one fulfilment proves the
  mechanism works — not that the operator is reliable, which only accumulates over time.

## Layout

```
gate/     BN254 precompile feasibility check
src/      BN254.sol (BLS verification), VRFCoordinator.sol, ExampleConsumer.sol
test/     Solidity test suites and generated vectors
script/   deployment script
daemon/   off-chain operator signer, and the canonical protocol module
tools/    key generation, key validation, independent fulfilment verification,
          test-vector generation and local end-to-end harnesses
docs/     PRD and the deployment record
```

## Reading the operator's record

**The on-chain counters are a convenience. The events are the proof.** `expireRequest` is
permissionless but nobody is paid to call it, so the `expired` counter under-reports misses
permanently. Derive the real miss rate from `RandomnessRequested`, `RandomnessFulfilled` and
the public `REQUEST_TIMEOUT_BLOCKS` constant. See the NatSpec on `Stats` and PRD §6.

## Licence

MIT.
