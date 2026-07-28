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

**Scaffold only. No contract logic has been written yet.** The feasibility gate has been run
and passed; the design is not settled and nothing here is usable.

- [x] Feasibility gate — BN254 precompiles verified on Arc testnet (see [`gate/`](gate/))
- [ ] PRD — see [`docs/PRD.md`](docs/PRD.md)
- [ ] Contract design
- [ ] Contracts
- [ ] Tests
- [ ] Testnet deployment

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

## What this does not claim

- It is not trust-minimised across multiple parties. There is one operator.
- Liveness is not guaranteed. Suppression is detectable, not preventable.
- Nothing has been audited. Nothing has been deployed.

## Layout

```
gate/     BN254 precompile feasibility check (complete)
src/      contracts (empty)
test/     tests (empty)
docs/     PRD and design notes
```

## Licence

MIT.
