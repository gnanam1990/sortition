# Deployment — Arc testnet

Every number on this page was read back from chain, not copied from a deploy log.

**Network:** Arc Public Testnet, chain ID **5042002**
**Deployed:** block 54,075,709
**Deployer:** `0x99B723eD097721036C08dd9DEe307286Df3A792D`
**Explorer:** [testnet.arcscan.app](https://testnet.arcscan.app)
**Status:** unaudited. One operator. Nothing here should hold value.

> **The RPC is the primary verification path. The explorer is secondary.** ArcScan has been
> erroring on transaction-hash lookups since 2026-07-25 (*"Something went wrong. Try
> refreshing the page or come back later."*), unacknowledged and unresolved as of writing.
> The links on this page may not render.
>
> Every claim below therefore carries the `cast` command that produces it. Nothing here
> requires the explorer to work.

## Setup

Every command on this page assumes these three variables. Set them once.

```bash
export ARC=https://rpc.testnet.arc.network
export COORD=0x17376aA831C70998F37522f00FD9f26d44977052
export CONSUMER=0x493297D2ca32D279e7E7dc08D691C0BB01Ca833e
```

**Pace these calls.** Arc's public RPC rate-limits aggressively and will interrupt a tight
loop with `-32011 request limit reached`. A second or two between calls is enough. See
[Arc's rate limiter](#arcs-rate-limiter-hit-live) below.

## Contracts

| Contract | Address | Deploy tx | Gas | Cost (USDC) |
|---|---|---|---:|---:|
| `VRFCoordinator` | [`0x17376aA831C70998F37522f00FD9f26d44977052`](https://testnet.arcscan.app/address/0x17376aA831C70998F37522f00FD9f26d44977052) | [`0x96cb6469…d499a0`](https://testnet.arcscan.app/tx/0x96cb6469ecc43aa76d7160588a4f24577b42f1eeb69cf1031c18089af7d499a0) | 3,256,791 | 0.065135820003256795 |
| `ExampleConsumer` | [`0x493297D2ca32D279e7E7dc08D691C0BB01Ca833e`](https://testnet.arcscan.app/address/0x493297D2ca32D279e7E7dc08D691C0BB01Ca833e) | [`0x41810b55…de5e71`](https://testnet.arcscan.app/tx/0x41810b559a566e05a9bc42e9d85bdaa8e41adcb1f2ed5b674a22cc5a89de5e71) | 229,806 | 0.004596120000229806 |

Confirm both are deployed and that the receipts say what the table says:

```bash
cast code $COORD --rpc-url $ARC | wc -c        # 12821 = 6409 bytes as hex (12818) + "0x" + newline
cast code $CONSUMER --rpc-url $ARC | wc -c

cast receipt 0x96cb6469ecc43aa76d7160588a4f24577b42f1eeb69cf1031c18089af7d499a0 --rpc-url $ARC
cast receipt 0x41810b559a566e05a9bc42e9d85bdaa8e41adcb1f2ed5b674a22cc5a89de5e71 --rpc-url $ARC
```

Both deployments landed in block 54,075,709 with `effectiveGasPrice` **20,000,000,001** — a
20 gwei base fee plus exactly **one wei** of priority. That is Arc's >100,000-gas rule
working as intended: above that threshold the priority fee must be collapsed by 1e9 or the
transaction hits `maxGasLimit` and fails.

### Registered operator key

Read from the deployed contract, not from the deploy command:

```bash
cast call $COORD "operatorPubkey()((uint256,uint256,uint256,uint256))" --rpc-url $ARC
cast call $COORD "operatorId()(bytes32)"             --rpc-url $ARC
cast call $COORD "REQUEST_TIMEOUT_BLOCKS()(uint256)" --rpc-url $ARC
cast call $COORD "MAX_CALLBACK_GAS()(uint256)"       --rpc-url $ARC
```

```
pubkeyX0  18135079057558911815349478439697877371305696033747077396731435028200399601950
pubkeyX1  12596167852106389240130941082960039318856206959773164727805534759509538662637
pubkeyY0  16274583839426316586526020317743651760503780880446737400146748888423136816548
pubkeyY1   9790629423032641761789689129865956941109788770798490209780820138042983998803

operatorId              0xb19191ffc3c2122ac7161d3a21e0600e5fd4b70a627639e5f522633845f579e7
REQUEST_TIMEOUT_BLOCKS  192
MAX_CALLBACK_GAS        2,000,000
```

The four coordinates are also readable individually as `pubkeyX0()` … `pubkeyY1()`, and
`operatorId` should equal `keccak256(abi.encode(x_c0, x_c1, y_c0, y_c1))`:

```bash
cast keccak $(cast abi-encode "f(uint256,uint256,uint256,uint256)" \
  18135079057558911815349478439697877371305696033747077396731435028200399601950 \
  12596167852106389240130941082960039318856206959773164727805534759509538662637 \
  16274583839426316586526020317743651760503780880446737400146748888423136816548 \
  9790629423032641761789689129865956941109788770798490209780820138042983998803)
```

The key passed the full `isInSubgroupG2` check twice before deployment — once locally with
py_ecc, and once by executing the coordinator's own Solidity on Arc via `eth_call`. Anyone
can repeat both, against the live key, without a secret and without mining anything:

```bash
.venv/bin/python tools/validate_pubkey.py "$(cast call $COORD \
  'operatorPubkey()((uint256,uint256,uint256,uint256))' --rpc-url $ARC)"
```

It is `immutable`; there is no setter and no rotation path.

### The deployed code is the code in this repository

The on-chain runtime is 6,409 bytes and differs from the local build artifact in exactly
448 bytes across 14 regions. Those are not unexplained: solc's own `immutableReferences`
declares **14 immutable read sites covering exactly 448 bytes**, and every differing byte
falls inside one of them. Nothing outside an immutable slot differs.

The values baked into those slots are the four public-key coordinates (2 sites each) and
`operatorId` (6 sites) — the validated key and nothing else.

```bash
forge build
cast code $COORD --rpc-url $ARC > /tmp/onchain.txt

python3 - <<'EOF'
import json
on  = open('/tmp/onchain.txt').read().strip().removeprefix('0x')
db  = json.load(open('out/VRFCoordinator.sol/VRFCoordinator.json'))['deployedBytecode']
loc = db['object'].removeprefix('0x')
imm = {b for slots in db['immutableReferences'].values()
         for s in slots for b in range(s['start'], s['start'] + s['length'])}
diff = {i // 2 for i in range(0, len(on), 2) if on[i:i+2] != loc[i:i+2]}
print("differing bytes          :", len(diff))
print("bytes in immutable slots :", len(imm))
print("differences OUTSIDE them :", len(diff - imm), "  <- must be 0")
EOF
```

## Lifecycle

One complete request, fulfilled. All four transactions below are real.

### 1. Request — block 54,092,397

[`0xee6324ad60f6277f4e3152c86f05599fc6cd9f7726608d9bcdb6ba02807cf976`](https://testnet.arcscan.app/tx/0xee6324ad60f6277f4e3152c86f05599fc6cd9f7726608d9bcdb6ba02807cf976)

`ExampleConsumer.draw(200000)` → `VRFCoordinator.requestRandomness`. **99,450 gas**,
0.001989000000099450 USDC.

```bash
cast receipt 0xee6324ad60f6277f4e3152c86f05599fc6cd9f7726608d9bcdb6ba02807cf976 --rpc-url $ARC
```

Emitted one log, topic0 `0xe3c0a750…01457` = `RandomnessRequested(uint256,address,uint256,uint32)`:

```
requestId        1
requester        0x493297D2ca32D279e7E7dc08D691C0BB01Ca833e
requestBlock     54092397   (0x0339626d)
callbackGasLimit 200000     (0x30d40)
```

Check the topic0 is what it claims to be:

```bash
cast keccak "RandomnessRequested(uint256,address,uint256,uint32)"
# 0xe3c0a7507b20da369ddefe94237aa86f0f2decabe6f0500f166e694d4ee01457
```

### 2. The seed becomes computable — block 54,092,398

Nothing happens on chain. The seed depends on `blockhash(requestBlock + 1)`, which does not
exist when the request is made — that is what stops a requester grinding it.

```
blockhash(54092398)  0x2f289369b32596a3a2a8c0fd727dff49a8996319dd279458a860c92050a808f4
seed                 0x20fb608b785cfa94a1025b274e630a62353b9f9f0e345aac08df5e0fbc594e6f
```

**`seedOf(1)` no longer works, and that is correct behaviour.** The `BLOCKHASH` opcode
exposes only the last 256 blocks, so once the chain moved past block 54,092,654 the
contract could no longer derive this seed. It now reverts:

```bash
cast call $COORD "seedOf(uint256)(bytes32)" 1 --rpc-url $ARC
# execution reverted, data: "0x92c3a58a"

cast keccak "SeedUnavailable()" | cut -c1-10
# 0x92c3a58a
```

That is the contract's own guard firing rather than silently returning a seed derived from
a zero block hash — the failure mode it was written to prevent. `fulfilmentMessage(1)`
reverts identically, for the same reason.

The underlying data is still verifiable forever over RPC, because `eth_getBlockByNumber` has
no such window. Reconstruct the seed yourself:

```bash
cast rpc eth_getBlockByNumber 0x339626e false --rpc-url $ARC | python3 -c "import sys,json;print(json.load(sys.stdin)['hash'])"
# 0x2f289369b32596a3a2a8c0fd727dff49a8996319dd279458a860c92050a808f4

# seed = keccak256(abi.encode(requestId, requester, blockhash))
cast keccak $(cast abi-encode "f(uint256,address,bytes32)" 1 \
  0x493297D2ca32D279e7E7dc08D691C0BB01Ca833e \
  0x2f289369b32596a3a2a8c0fd727dff49a8996319dd279458a860c92050a808f4)
# 0x20fb608b785cfa94a1025b274e630a62353b9f9f0e345aac08df5e0fbc594e6f
```

### 3. Fulfilment submitted — block 54,092,427

The daemon signed and submitted with **162 of 192 blocks remaining**. 30 blocks (15 seconds)
after the request, all of it including rate-limit backoff — see below.

### 4. Fulfilment included — block 54,092,441

[`0x84adf504ff21d844d8eb7f7fe97a47fa8084e8f9fb769d97127a48a6f4123ab3`](https://testnet.arcscan.app/tx/0x84adf504ff21d844d8eb7f7fe97a47fa8084e8f9fb769d97127a48a6f4123ab3)

`VRFCoordinator.fulfillRandomness`. **254,619 gas**, 0.005092380000254619 USDC.

```bash
cast receipt 0x84adf504ff21d844d8eb7f7fe97a47fa8084e8f9fb769d97127a48a6f4123ab3 --rpc-url $ARC
```

Submitted by `0x99B723eD…A792D`. Worth noting that this address is not privileged:
`fulfillRandomness` is permissionless because the BLS signature is the authorisation, not
the sender. Any relayer could have submitted the same bytes.

Two logs, in order:

```
[0] 0x493297D2…833e  Drew(uint256,bytes32)                 topic0 0x65b1e668…07640
    requestId  1
    randomness 0xdb6a91c163cdf5db57b1efa9d132bd3a0630611146cf27c72760111b97ac0c0c

[1] 0x17376aA8…7052  RandomnessFulfilled(uint256,bytes32,bool)  topic0 0x003656de…59e59
    requestId          1
    randomness         0xdb6a91c163cdf5db57b1efa9d132bd3a0630611146cf27c72760111b97ac0c0c
    callbackSucceeded  true
```

All three topic0 hashes were checked against `keccak256` of their signatures and match:

```bash
cast keccak "RandomnessFulfilled(uint256,bytes32,bool)"  # 0x003656de09cdaebb…cdea59e59
cast keccak "Drew(uint256,bytes32)"                      # 0x65b1e6689f55de43…031f07640
```

### Timing

Every figure below comes from block timestamps, not from an assumed block time:

```bash
for b in 0x339626d 0x339628b 0x3396299; do
  cast rpc eth_getBlockByNumber $b false --rpc-url $ARC \
    | python3 -c "import sys,json;b=json.load(sys.stdin);print(int(b['number'],16), int(b['timestamp'],16))"
  sleep 2
done
# 54092397 1785243972   request
# 54092427 1785243987   submission
# 54092441 1785243995   inclusion
```

| | Blocks | Seconds |
|---|---:|---:|
| Request → submission | 30 | 15 |
| Request → inclusion | 44 | 23 |
| **Margin at submission** | **162** | ~86 |
| **Margin at inclusion** | **148** | ~79 |

The run consumed **22.9%** of the 192-block window. Seconds are from actual block
timestamps, not from multiplying by an assumed block time.

## The callback delivered what the coordinator verified

This is the claim the whole design rests on, so it is checked from four directions rather
than asserted.

| Source | Command | Value |
|---|---|---|
| `VRFCoordinator.randomnessOf(1)` | `cast call $COORD "randomnessOf(uint256)(bytes32)" 1 --rpc-url $ARC` | `0xdb6a91c1…ac0c0c` |
| `ExampleConsumer.lastRandomness()` | `cast call $CONSUMER "lastRandomness()(bytes32)" --rpc-url $ARC` | `0xdb6a91c1…ac0c0c` |
| `RandomnessFulfilled` event data | `cast receipt 0x84adf504…23ab3 --rpc-url $ARC` | `0xdb6a91c1…ac0c0c` |
| `Drew` event, emitted by the consumer | same receipt, log `[0]` | `0xdb6a91c1…ac0c0c` |

Full value: `0xdb6a91c163cdf5db57b1efa9d132bd3a0630611146cf27c72760111b97ac0c0c`

Supporting read-backs:

```bash
cast call $COORD    "requests(uint256)(address,uint48,uint32,uint8)" 1 --rpc-url $ARC
cast call $COORD    "operatorStats()(uint64,uint64,uint64)"            --rpc-url $ARC
cast call $COORD    "pendingCount()(uint256)"                          --rpc-url $ARC
cast call $COORD    "isExpired(uint256)(bool)" 1                       --rpc-url $ARC
cast call $CONSUMER "lastRequestId()(uint256)"                         --rpc-url $ARC
cast call $CONSUMER "hasResult()(bool)"                                --rpc-url $ARC
cast call $CONSUMER "activeRequestId()(uint256)"                       --rpc-url $ARC
```

```
requests(1)     → requester 0x493297D2…833e, requestBlock 54092397,
                  callbackGasLimit 200000, status 2 (Fulfilled)
operatorStats() → requested 1, fulfilled 1, expired 0
pendingCount()  → 0
isExpired(1)    → false
consumer.lastRequestId()   → 1
consumer.hasResult()       → true
consumer.activeRequestId() → 0   (commitment released)
```

### Verified independently of the contract

The contract says the signature verified. That is the contract's own opinion, so it was
checked with a different implementation, from chain data alone.

The signature was extracted from the fulfilment transaction's calldata:

```bash
cast tx 0x84adf504ff21d844d8eb7f7fe97a47fa8084e8f9fb769d97127a48a6f4123ab3 input --rpc-url $ARC
```

```
selector  0x9502dcdf   = fulfillRandomness(uint256,(uint256,uint256))
sig.x     19554533432006289269039256401589351040058878674087290822057419249547640400857
sig.y      8605922667394351031084367410574243820142206928881071669083257930246086249124
```

Decode it, and confirm the selector and the randomness derivation:

```bash
cast calldata-decode "fulfillRandomness(uint256,(uint256,uint256))" \
  $(cast tx 0x84adf504ff21d844d8eb7f7fe97a47fa8084e8f9fb769d97127a48a6f4123ab3 input --rpc-url $ARC)

cast sig "fulfillRandomness(uint256,(uint256,uint256))"    # 0x9502dcdf

# randomness = keccak256(abi.encode(sig.x, sig.y))
cast keccak $(cast abi-encode "f(uint256,uint256)" \
  19554533432006289269039256401589351040058878674087290822057419249547640400857 \
  8605922667394351031084367410574243820142206928881071669083257930246086249124)
# 0xdb6a91c163cdf5db57b1efa9d132bd3a0630611146cf27c72760111b97ac0c0c
```

- It is on `y² = x³ + 3`. The G1 cofactor is 1, so on-curve **is** a complete subgroup check.
- `keccak256(abi.encode(x, y))` reproduces `randomnessOf(1)` exactly.
- The message was rebuilt from chain data alone — chain id, coordinator address, request id,
  and `blockhash(54092398)` — and **py_ecc's own pairing** confirms
  `e(sig, G2) · e(−H(m), pubkey) == 1` against the registered key.

All of that is packaged, so anyone can repeat it against the live chain:

```bash
.venv/bin/python tools/verify_onchain_fulfilment.py \
  0x17376aA831C70998F37522f00FD9f26d44977052 1 \
  0x84adf504ff21d844d8eb7f7fe97a47fa8084e8f9fb769d97127a48a6f4123ab3
```

```
--- BLS verification with py_ecc, NOT with src/BN254.sol
  PASS  e(sig, G2) * e(-H(m), pubkey) == 1

VERDICT: the fulfilment is genuine, verified independently of the contract.
```

It deliberately does not call `seedOf()` or `fulfilmentMessage()`, rebuilding both from
`eth_getBlockByNumber` instead — so it keeps working after the block hash ages out, which
is why it can still be run today.

The operator's signature is genuine, and that conclusion does not depend on trusting
`src/BN254.sol`.

## Total cost

| Step | Gas | USDC |
|---|---:|---:|
| `VRFCoordinator` deploy | 3,256,791 | 0.065135820003256795 |
| `ExampleConsumer` deploy | 229,806 | 0.004596120000229806 |
| Request | 99,450 | 0.001989000000099450 |
| Fulfilment | 254,619 | 0.005092380000254619 |
| **Total** | **3,840,666** | **0.076813320003840668** |

The coordinator deployment is 85% of that, and the constructor's one-time G2 subgroup check
is most of it. That is the price of the register-and-store decision, paid once so that every
fulfilment afterwards costs ~255,000 gas instead of ~1.9 million.

## Arc's rate limiter, hit live

The daemon hit Arc's public-RPC rate limiter **repeatedly** during this run — HTTP 429 /
`-32011 request limit reached` on `estimate_gas`, on `requests`, and on `get_logs` — and
backed off through every one of them.

*(The per-call breakdown above is from the operator's daemon log, which is not on chain. The
timings below are derived from chain, and the limiter itself was independently confirmed —
see the last paragraph of this section.)*

It still submitted with **162 of 192 blocks remaining**, and 15 seconds elapsed between the
request landing and the fulfilment being submitted, backoff included.

This is the documented Arc failure mode being handled against a live network rather than in a test.
`-32011` was recorded as the live blocker for indexers on Arc's public RPC and had no
official recommended polling interval; the daemon treats it as an expected operating
condition — exponential backoff with jitter, capped, six attempts — rather than a crash.

It is not a hypothetical: **the same limiter interrupted the read-back for this document**,
on plain `cast call` requests, and had to be paced around.

Two mitigations were already in the daemon before this run, both aimed at request volume:
`eth_getLogs` is chunked to 64 blocks, and the discovery window is bounded to
`REQUEST_TIMEOUT_BLOCKS + 16`, because a request older than the timeout cannot be fulfilled
anyway. A polling interval of 5 seconds was used; the 1-second default issues roughly four
`eth_getLogs` calls per poll and is too aggressive for Arc's public RPC. Whether those
specific mitigations are what kept this run inside its window is not something one sample
can establish.

## What this proof does NOT show

Read this part. The section above is one successful transaction and it is easy to
over-read.

**One fulfilment proves the mechanism. It proves nothing about the operator's fulfilment
rate.** A rate only accumulates over time, and one sample is not a rate. Worse, the counter
that would measure it under-reports by construction: `expireRequest` is permissionless but
nobody is paid to call it — the service is free, so a requester gets no refund, and the
operator will not mark their own misses. A genuine miss can therefore sit in
`pendingCount()` forever and never reach `expired`. The honest number comes from scanning
`RandomnessRequested` against `RandomnessFulfilled` with the public `REQUEST_TIMEOUT_BLOCKS`
constant. The on-chain counters are a convenience; the events are the proof.

**The operator key is single and immutable.** Anyone holding it can compute any output the
moment `blockhash(requestBlock + 1)` exists — before anyone else sees it. They cannot
*change* an output, because BLS is deterministic and there is exactly one valid signature
per request. But unpredictability is the product of a randomness service, and a draw one
party can see in advance is a rigged draw even though the number was never chosen.
Integrity survives; the guarantee does not. There is no rotation path, so a compromised key
means a new coordinator and a consumer migration.

**Nobody has integrated this.** The one request above came from an example consumer written
in this repository, deployed by the same account that deployed the coordinator, driven by
its own author. That is a self-test, not adoption. It demonstrates that the mechanism works;
it says nothing about whether anyone wants it.

**Nothing here has been audited.** No third party has reviewed the BLS library, the
coordinator, or the hand-written Fp2 and Jacobian arithmetic behind the subgroup check.

**One run is not liveness.** The daemon handled the rate limiter once, at low load, on a
testnet with no competition for block space. It has never been tested against sustained
load, a `txpool is full` condition, or a validator outage.

## Verifying all of it in one pass

Each claim above carries its own command. This is the short version — the whole page in
one block, needing nothing but `cast`, and never the explorer.

```bash
export ARC=https://rpc.testnet.arc.network
export COORD=0x17376aA831C70998F37522f00FD9f26d44977052
export CONSUMER=0x493297D2ca32D279e7E7dc08D691C0BB01Ca833e
export FULFIL=0x84adf504ff21d844d8eb7f7fe97a47fa8084e8f9fb769d97127a48a6f4123ab3
export REQUEST=0xee6324ad60f6277f4e3152c86f05599fc6cd9f7726608d9bcdb6ba02807cf976

# the deployment
cast call $COORD "operatorPubkey()((uint256,uint256,uint256,uint256))" --rpc-url $ARC ; sleep 2
cast call $COORD "operatorId()(bytes32)"                               --rpc-url $ARC ; sleep 2
cast call $COORD "REQUEST_TIMEOUT_BLOCKS()(uint256)"                   --rpc-url $ARC ; sleep 2

# the lifecycle
cast receipt $REQUEST --rpc-url $ARC ; sleep 2
cast receipt $FULFIL  --rpc-url $ARC ; sleep 2

# the result, from both sides
cast call $COORD    "requests(uint256)(address,uint48,uint32,uint8)" 1 --rpc-url $ARC ; sleep 2
cast call $COORD    "randomnessOf(uint256)(bytes32)" 1                 --rpc-url $ARC ; sleep 2
cast call $COORD    "operatorStats()(uint64,uint64,uint64)"            --rpc-url $ARC ; sleep 2
cast call $CONSUMER "lastRandomness()(bytes32)"                        --rpc-url $ARC ; sleep 2
cast call $CONSUMER "hasResult()(bool)"                                --rpc-url $ARC
```

And the part that does not take the contract's word for it:

```bash
.venv/bin/python tools/verify_onchain_fulfilment.py $COORD 1 $FULFIL
```

**Pace these.** The rate limiter is live and will interrupt a tight loop — the `sleep 2`
calls are not decoration. `tools/verify_onchain_fulfilment.py` paces itself.

Two commands on this page will **not** work any more, by design: `seedOf(1)` and
`fulfilmentMessage(1)` both revert with `SeedUnavailable()` now that the seed's block hash
has aged past the 256-block `BLOCKHASH` window. Reconstruct the seed from
`eth_getBlockByNumber` instead, as shown in step 2 — that path has no expiry.
