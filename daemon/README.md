# Operator daemon

Watches `RandomnessRequested`, reconstructs the seed and message exactly as the contract
does, signs with the operator BLS key, and submits `fulfillRandomness`.

```bash
export SORTITION_BLS_SECRET=0x...        # operator BLS scalar — see below
export SORTITION_TX_KEY=0x...            # separate key, pays gas only
.venv/bin/python daemon/operator_daemon.py \
    --rpc https://rpc.testnet.arc.network \
    --coordinator 0xYourCoordinator
```

| File | What it is |
|---|---|
| `protocol.py` | The **only** Python implementation of hash-to-curve, the seed and the signed message. Everything else imports from here. |
| `operator_daemon.py` | The daemon. |
| `test_daemon.py` | Tests against a local anvil it spawns itself. |

## Two keys, and only one of them matters

These are different things and conflating them is the easiest way to lose the system.

**The BLS operator secret** is the entire security of the service. It is a scalar, not an
Ethereum key, and it never signs a transaction. It never touches the chain — only its
signatures do.

**The transaction key** pays gas. It is *not* privileged: `fulfillRandomness` is
permissionless because the BLS signature is the authorisation, not the sender. Anyone can
relay a valid signature.

That has a useful consequence. **The gas-paying hot wallet does not need to live wherever
the BLS key lives.** A compromised transaction key costs you the gas balance and nothing
else. Keep them separate, fund the transaction key thinly, and treat only the BLS key as
irreplaceable.

## Where the BLS key should live

The daemon reads it from, in order:

1. `SORTITION_BLS_SECRET` — an environment variable, ideally injected at start by a secret
   manager (systemd `LoadCredential`, Vault, 1Password Connect, SOPS) and never written to
   disk in cleartext.
2. `SORTITION_BLS_KEYFILE` — a path to a file **outside this repository**. The daemon
   refuses to read it if the mode is group- or world-readable.

There is no default and no fallback. If neither is set, the daemon exits.

**It is never in this repository, and there is no mechanism to put it there.** The only
scalar in the repo is the test one in `test/Vectors.sol`, labelled as controlling nothing,
and using it requires the explicit `--insecure-test-key` flag, which logs a warning and is
deliberately visible in the process list.

An HSM would be better and is not currently available: BN254 BLS is not a signing scheme
that mainstream KMS and HSM products support. That is a real gap, not an oversight.

## What happens if the host is compromised

Be precise about this, because the obvious answer is wrong in an interesting way.

**Integrity survives. Unpredictability does not.**

An attacker holding the BLS key **cannot change any output.** The signature is deterministic
— for a given request there is exactly one valid signature, and it is the same one the
honest operator would have produced. Publishing it early, late, or not at all does not
change its value. The property the whole design rests on is not broken by key theft.

What the attacker gains is **advance knowledge**. Once a request's seed block is mined, the
key holder can compute the output before anyone else sees it. For most consumers that is
sufficient to extract the value: knowing the winning number before publication is usually as
good as choosing it. They can also fulfil requests on the operator's behalf, which is
harmless, and they learn every future output for as long as they hold the key.

**Do not read "integrity survives" as a lesser failure.** Unpredictability is the product of
a randomness service. A draw that one party can see in advance is a rigged draw even though
the number was never chosen. Integrity survives; the guarantee does not.

This is why prompt fulfilment is a security property and not only good service. The window
in which a key holder knows the output and nobody else does opens at `requestBlock + 2` and
closes when the fulfilment lands — bounded above by `REQUEST_TIMEOUT_BLOCKS`, so at most 190
blocks or about 101 seconds. Every block the daemon shaves off that is a block of exclusive
advantage removed.

**There is no recovery path in v1.** The public key is `immutable` in the coordinator, by
design — a rotation path would itself be an output-grinding vector unless requests are bound
to a key epoch. So a compromised key cannot be replaced. The only remedy is to deploy a new
coordinator with a new key and have consumers migrate to it, abandoning the old deployment
and its fulfilment history.

Plan accordingly: the key is worth exactly as much as every future draw made through this
coordinator.

## Arc-specific handling

Both of these come from recorded Arc failure modes, not general caution.

**The base fee is fetched immediately before every submission and never cached.** A stale
base fee gets the transaction rejected or stuck.

**Above 100,000 gas the priority fee is collapsed by 1e9.** A normal priority fee multiplied
across a large gas amount pushes the total past `maxGasLimit` and the transaction fails.
Every fulfilment is over 100,000 gas, so on this daemon that is the normal path, not an edge
case.

Transient failures are backed off, not treated as fatal: `-32011 request limit reached`
(public RPC hard limit), `-32003 txpool is full`, `rpc cooling`, HTTP 429, and connection
timeouts. Backoff is exponential with jitter, capped, six attempts. `eth_getLogs` is issued
in 64-block chunks because Arc's public RPC rate-limits wide ranges aggressively.

## Deadlines

`REQUEST_TIMEOUT_BLOCKS` is 192, which at Arc's measured 0.5335 s block time is about 102
seconds. The daemon reads the constant from the contract rather than hardcoding it.

Every request is classified on each poll:

| Level | Blocks remaining | Meaning |
|---|---|---|
| `OK` | > 96 | Normal |
| `WARN` | ≤ 96 | Half the window gone |
| `AT_RISK` | ≤ 38 | About 20 seconds left |
| `MISSED` | ≤ 0 | Deadline passed |

A miss is logged at `ERROR` with the request id. **This is the one thing the design counts
against the operator, so the daemon must never produce one quietly** — a silent miss is
indistinguishable from deliberate withholding to anyone reading the chain, which is exactly
the accusation the operator cannot refute.

## Restart safety

The daemon does not rely on having been running when a request arrived.

**Backfill is bounded.** On start it scans the last `REQUEST_TIMEOUT_BLOCKS + 16` blocks. A
request older than the timeout cannot be fulfilled, so there is never a reason to scan
further back — the daemon can be down for a week and still start cheaply.

**Events discover, contract state decides.** Logs are used to find candidate request ids;
whether to act is always decided by reading `requests(id).status` on chain. A request is only
signed for if the contract itself still says `Pending`.

**The state file is write-ahead.** `{request_id → tx hash, nonce, block, signature}` is
written and fsync-replaced *before* the transaction is sent, so a crash between signing and
sending still leaves a record.

### Signed and submitted, but the receipt was never seen

This is the case that matters, and it is handled by asking the chain rather than guessing.
On restart, for each in-flight record:

1. **Read the request's status first.** It is the only authority on whether the work is done.
   - `Fulfilled` → clear the record. Done, whether by us or by a relayer.
   - `Expired` or unknown → clear the record. Nothing to do.
   - `Pending` → the work is still outstanding; continue.
2. **Then look for the transaction.**
   - Receipt exists, reverted → clear and retry.
   - No receipt, submitted less than 4 blocks ago → still plausibly in the mempool; wait.
   - No receipt, older than that → treat as dropped, clear and resubmit.

**Resubmission is safe because BLS is deterministic.** Re-signing produces the byte-identical
signature, so a resubmitted transaction carries exactly the same payload. There is no
possibility of two different valid outputs for one request. The worst case is that both
transactions land and the second reverts with `RequestNotPending` — wasted gas, never a
corrupted record and never a second callback, because the coordinator marks the request
fulfilled before it hands control to the consumer.

## Tests

```bash
.venv/bin/python daemon/test_daemon.py
```

Spawns its own anvil, deploys a coordinator and consumer, and tears down afterwards. Nothing
touches Arc.

The first test is the one that protects the rest: it asserts the daemon's seed and message
are **byte-identical** to the contract's `seedOf` and `fulfilmentMessage`, checked against a
live contract. If either side is ever edited without the other, that test fails. A silent
divergence there would produce signatures that are perfectly valid over the wrong message —
they would verify against nothing, and the daemon would look broken rather than wrong.
