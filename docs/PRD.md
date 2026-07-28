# Verifiable Randomness on Arc — PRD v1.0

**Status:** design · pre-build
**Chain:** Arc testnet 5042002
**Team:** solo
**Gate cleared:** BN254 precompiles `0x06`/`0x07`/`0x08` verified present, correct and
EIP-1108 priced on Arc (2026-07-28). The `ecpairing` call itself costs 113,000 gas for a
2-pairing check; a full fulfilment costs more than that, and how much more is a design
decision rather than a given — see §5.

---

## 1. Problem

Arc has no verifiable randomness. This is not an inference — it is the recorded state of
the ecosystem.

- `elegant.eth` asked directly (2026-04-16) whether Arc has native VRF support. No answer.
- `creepy` asked for a randomness contract address (2026-07-18). Tim confirmed none exists
  and supplied a `CREATE2` + `prevrandao` recipe, with an explicit warning that it **must
  not be used for gambling or security-critical logic**.
- Chainlink VRF was described as something that "can be expected." It never went live.

Across roughly 545 catalogued Arc projects — 364 in the Lepton/Agora showcase and 181 in
the Discord ecosystem directory — no randomness service exists. Meanwhile 57 prediction
markets are live, plus launchpads, allocation systems and mints, all of which need to pick
winners.

They are all using `prevrandao`, and `prevrandao` is grindable. The block proposer sees the
value before anyone else. If the outcome is unfavourable, they can drop the block and
propose again. The attack is silent, repeatable, and cheap, and there is no way for a
participant to detect that it happened.

## 2. Insight & core mechanism

The realistic fix for a solo operator is not to eliminate operator influence. It is to
**reduce the operator's power to a single, visible, countable action.**

BLS signatures over BN254 are deterministic. For a given message and key, exactly one valid
signature exists. There is no nonce to vary, no retry that produces a different result.

This has a precise consequence: **the operator cannot choose the output.** They can compute
it, and they can decline to publish it — but they cannot produce a different one. Grinding
is not weakened here, it is structurally impossible.

Withholding remains. The operator can see the output before publishing and stay silent if
they dislike it. But an unfulfilled request sits on chain, unanswered, permanently, with a
timestamp. A consumer can read an operator's entire fulfilment history before trusting them
with anything.

So the mechanism trades an invisible attack for a visible one:

| | `prevrandao` today | This design |
|---|---|---|
| Operator can choose the output | Yes, by re-proposing | **No — deterministic** |
| Operator can suppress an output | n/a | Yes |
| Suppression is detectable | n/a | **Yes, on chain, permanently** |
| Participant can verify the result | No | **Yes, one pairing check** |

**Seed construction.** The seed for request `i` is
`keccak256(requestId, requester, blockhash(requestBlock + 1))`.

The future block hash matters. It does not exist when the requester submits, so a requester
cannot try seeds until they find one they like. The operator cannot grind because the
signature is deterministic. Neither side can steer the input.

## 3. Users & jobs

| User | Job |
|---|---|
| Launchpad / allocation contract | Pick `k` winners from `n` entrants in a way the losers can check |
| Prediction market | Resolve a tie, select an auditor, sample a set |
| NFT mint | Assign token traits without the team front-running rare ones |
| Game contract | Any outcome that is not supposed to be predictable |
| **A participant who lost** | Confirm the draw was not steered, without trusting the operator or the app |

That last row is the one that matters. Every other user wants randomness. Only the loser
needs it to be *verifiable*, and they are the reason the service has a reason to exist.

## 4. Scope (MoSCoW)

**MUST**

1. `BN254.sol` — pairing-based BLS verification library. `verify(pubkey, message, signature)`
   reducing to one 2-pair `ecpairing` call.
2. `VRFCoordinator.sol` — `requestRandomness()` emits a request; `fulfillRandomness()`
   verifies the BLS signature on chain and rejects anything that does not check out.
   Rejection is unconditional: an unverifiable signature is not stored, not callbacked, not
   accepted with a warning.
3. Consumer callback interface, with a gas limit set by the requester so a reverting
   consumer cannot brick fulfilment.
4. Operator daemon — watches request events, computes the seed, signs, submits.
5. **On-chain fulfilment accounting.** Per-operator counters for requests received,
   fulfilled, and expired-unfulfilled, readable by any contract. This is the design's
   accountability mechanism and is not optional.

**SHOULD**

6. Request expiry. After `T` blocks an unfulfilled request is permanently marked expired and
   increments the miss counter. The requester can reclaim any prepaid fee.
7. A worked allocation example — pick `k` of `n` — as the reference consumer.
8. A public verification script: given a request id, fetch the signature from chain and
   check it independently, without using this project's code.

**COULD**

9. Multi-operator threshold (`t`-of-`N`). The contract shape does not change — only the
   public key does, from a single key to an aggregated group key. Designed for now, built
   later.
10. Fee market.

**WON'T (v1)**

- Operator bonding and slashing. That requires an operator registry, stake accounting and a
  challenge mechanism, and is a larger system than the VRF itself.
- Any use for gambling. Not a technical limit — a stated position, consistent with the
  warning already on record from Arc staff.

## 5. Architecture

```
consumer contract
      │  requestRandomness(callbackGasLimit)
      ▼
VRFCoordinator.sol ──emits──▶ RandomnessRequested(id, requester, block)
      ▲                                    │
      │  fulfillRandomness(id, sig)        │  watched
      │                                    ▼
      └──────────────────────────  operator daemon (off chain)
                                     signs keccak(id, requester, blockhash(b+1))
```

On chain: request records, the operator public key, BLS verification, fulfilment counters,
the callback. Off chain: the key and the signing. The key never touches the chain; only
signatures do, and every signature is checked before it is believed.

**Cost.** Cost depends on whether the operator key is validated per call or once at
registration. A full `verify()` including the G2 subgroup check is 1,905,727 gas
(~0.038 USDC at a 20 gwei base fee); with the key pre-validated and stored, a fulfilment is
122,815 gas (~0.0025 USDC). The subgroup check is 93% of the full cost.

This design registers the operator key once, validating it in full at that moment, and uses
the pre-validated path thereafter. That is safe only if every path by which a key can enter
the contract — constructor, setter, rotation — runs the full subgroup check. If any path
skips it, the stored verdict is a lie and the fulfilment path validates nothing.

The earlier figure of ~138,000 gas in this document was the pairing call plus intrinsic and
calldata only. It was never wrong about the pairing; it was incomplete about the
verification, and it is correct only for the pre-validated path. That path is now a
deliberate decision rather than an assumption.

**Measured end to end (stage 2).** The figures above are the verification call. A whole
`fulfillRandomness` transaction, measured from a real receipt on a local chain rather than
estimated, costs **183,906 gas** with no consumer callback and **252,884 gas** delivering to
a consumer that writes three storage slots — about **0.0037 to 0.0051 USDC** at a 20.2 gwei
gas price, or roughly 118 to 163 fulfilments per 30M gas block. `requestRandomness` costs
77,691 gas. Gas is not a constraint on this design; the register-and-store decision is what
made that true.

Arc's base fee must be re-fetched before every submission and never cached — this is a
documented Arc-specific failure mode, not a general precaution.

## 6. Security & attack model

| Attack | Outcome |
|---|---|
| Operator tries to choose the output | **Impossible.** BLS is deterministic; one valid signature exists |
| Operator withholds an unfavourable output | **Possible.** Visible on chain as an expired request, counted permanently against them |
| Operator forges a signature | **Impossible without the key.** Verification is a pairing check against the published public key |
| Requester grinds the seed | **Impossible.** The seed depends on a block hash that does not exist at request time |
| Consumer contract reverts in the callback | Fulfilment still succeeds; the callback is gas-limited and its failure is isolated |
| Operator key compromised | **Total failure.** The holder can produce valid signatures for any request. Mitigated only by moving to a threshold key |
| Operator goes offline | Requests expire. No funds are lost; consumers must handle expiry |

**The honest summary.** A single operator cannot rig an outcome, but can refuse to produce
one. That is strictly better than a block proposer who can silently re-roll, and strictly
worse than a threshold set where no individual can do either.

## 7. Honest limits

- **This is a one-of-one operator.** Calling it "decentralised" would be false. The
  documentation, the site and the README will say single-operator plainly, in the first
  paragraph, not in a footnote.
- **Withholding is not solved, only made visible.** A consumer for whom a suppressed draw
  is unacceptable should not use v1.
- **Key compromise is unrecoverable in v1.** There is no rotation path and no threshold.
- **Demand is unproven.** Two people asked for this in nine months. That the gap is real is
  well evidenced; that anyone will integrate is not.
- **Chainlink may ship VRF on Arc mainnet** and make this redundant. That is outside my
  control and worth stating rather than ignoring.
- **`prevrandao` is not useless** for low-value uses. This service is for cases where
  someone loses something when the draw is steered.

## 8. Demo

One request, start to finish, on chain.

1. An allocation contract with 500 entrants and 100 places calls `requestRandomness`.
2. The request appears on chain with its block number. Nothing is decided yet.
3. The operator signs and submits. The coordinator verifies the pairing on chain and stores
   the result.
4. Winners are derived from the seed by a pure function anyone can re-run.
5. **The proof beat.** An independent script — not this project's code — fetches the
   signature from chain, recomputes the seed, and verifies the pairing. It returns true. Then
   a single byte of the signature is flipped and it returns false.

Step 5 is the whole product. Everything before it is plumbing.

## 9. Open questions

1. **Expiry window `T`.** Too short and honest operator latency looks like withholding. Too
   long and consumers wait. Needs a measured number from Arc block times, not a guess.
2. **Fee model.** Free is simplest and matches an unproven-demand v1. A fee creates an
   incentive to fulfil. Undecided.
3. **Callback gas limit ceiling.** Requester-supplied, but a maximum is needed so a request
   cannot be made unfulfillably expensive.
4. **Key storage.** The operator key is the whole system. Where it lives, and what happens
   on rotation, is unanswered.
5. **Does an on-chain miss counter actually change anyone's behaviour**, or is it a metric
   nobody reads? The design leans on it. That assumption is untested.
