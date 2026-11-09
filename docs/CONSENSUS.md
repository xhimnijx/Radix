# Consensus specification

**Status: draft, unimplemented.** This is a specification of what a mainnet would have
to do, written down so the parameters can be argued about with numbers rather than
intuition. Nothing here runs: `radix_testnet` mines a placeholder block with no
difficulty target and no peers.

Normative words follow RFC 2119.

> Research prototype. No value, no security claim.

---

## 1. The constraint that sets everything else

A tagged spend is **38,656 bytes** — one ring signature of 32 KB plus the tag and the
transaction envelope. Untagged it is 32,512 B. That single number bounds throughput,
block size, and chain growth together:

| throughput | blocks/day at 120 s | bytes/day | stored per year |
|---|---|---|---|
| 1 tx per block | 720 | 28 MB | **10 GB** |
| 5 tx per block | 720 | 139 MB | **51 GB** |
| 10 tx per block | 720 | 279 MB | **102 GB** |
| 10 tx per block, 30 s blocks | 2,880 | 1.1 GB | **407 GB** |
| **with amounts hidden, 26.49 KB/tx** (SMILE §4.5, 2-in/2-out) | 720 | 19 MB | **7 GB** |
| **with amounts hidden, 10 tx/block** | 720 | 191 MB | **69 GB** |

A chain people are expected to download has a practical ceiling around 100–300 GB, so
the design target is **0.05–0.5 transactions per second** until proofs shrink or are
aggregated.

The last two rows matter: the paper's own confidential-transaction proof (2 inputs,
2 outputs, ring size 1024, amounts hidden) is **26.49 KB**, smaller than our current
31.75 KB for one input with visible amounts. So hidden amounts do not threaten the size
budget — our unimplemented compression does. See `vault/Amount Confidentiality.md`. Monero reaches ~20 tx/s because its proofs are ~2.5 KB per input; ours are
fifteen times larger. This is a property of the proof system, not of the parameters, and
no block-time choice can fix it.

---

## 2. Block time

**AUTHORITATIVE: 120 seconds.**

Rationale, in order of weight:

1. **Block time is not the throughput knob.** Throughput is `block size / block time`,
   and chain growth is `block size × blocks per day`. Halving the block time doubles
   growth for the same throughput.
2. **Block time is only the latency knob for *first inclusion*.** A user waits on
   average 60 s at a 120 s target. Confirmation *confidence* does not improve with
   faster blocks; every confirmation halves the reorganisation probability regardless.
   Most of the perceived speed of a modern wallet comes from showing a pending
   transaction immediately, which is a UI property.
3. **Larger losses.** A stale block wastes its full size. At 32 KB per transaction,
   orphans are expensive, so the orphan rate matters more than in Bitcoin.
4. 120 s gives roughly a 1% orphan rate at realistic propagation delays — but **that
   figure is an assumption until there is a peer-to-peer layer to measure it against.**

**MUST NOT** be changed to increase throughput. If more capacity is needed, raise the
block size.

---

## 3. Difficulty adjustment

**AUTHORITATIVE: LWMA over 90 blocks, adjusted every block, clamped to 2× either
direction.**

### 3.1 Target

`T = 120` seconds per block.

### 3.2 Formula

Let `t_i` be the timestamp of block `i` and `n = 90`. For the block at height `h`,
using the most recent `n` solve times `s_i = t_i − t_{i−1}`:

```
LWMA = Σ_{i=h−n+1}^{h} ( i − (h−n) ) · s_i  /  Σ_{i=h−n+1}^{h} ( i − (h−n) )

next_difficulty = previous_difficulty · T / LWMA,   clamped to [previous/2, previous·2]
```

The linear weighting means the newest solve time counts `n`× the oldest, which is what
makes the adjustment respond within an hour of a hashrate change instead of a day.

### 3.3 Why not the Bitcoin rule

Bitcoin adjusts every 2,016 blocks. At a 120 s target that is 28 hours, and the clamp is
4×. A network with a hashrate near zero — which is where any new coin starts — can be
swept by one participant joining or leaving. The adjustment MUST be per-block and MUST
be clamped.

### 3.4 Timestamp rules

A block's timestamp `t` MUST satisfy:

1. `t > median(t_{h−11}, …, t_{h−1})` — the median time past rule,
2. `t ≤ now + 7200` seconds.

Rule 1 is not optional: without it a miner can lie forwards, drag the LWMA up, and then
mine cheaply when difficulty collapses back. Rule 2 bounds the lie in the other
direction.

Honest limitation: **a majority of hashrate can still manipulate both.** No timestamp
rule fixes that, and it belongs in `SECURITY-NOTES.md` rather than in a parameter.

### 3.5 The bootstrap problem

The genesis difficulty must be chosen from an assumed hashrate. If it is too hard, the
coin stalls until the clamp relaxes it; if it is too soft, thousands of blocks are mined
in minutes by whoever starts first — an instamine in everything but name.

**NOT DECIDED.** The clamp bounds the damage but does not remove it. Options are a low
genesis difficulty with a mandatory slow start (difficulty rises on a schedule for the
first `N` blocks regardless of measured speed), or a proof-of-work-free bootstrapping
period. This needs a decision before launch, and it is the parameter most likely to be
got wrong.

---

## 4. Block size

**AUTHORITATIVE: dynamic, on Monero's model.**

```
free_limit   = median(block sizes over the last 100 blocks)
penalty(b)   = max(0, (b / free_limit) − 1)²
reward(b)    = base_reward / (1 + penalty(b))
```

A miner may exceed `free_limit`, but pays for it in forgone reward, which is a market
price on block size rather than a hard cap. At 38 KB per transaction, `free_limit` starts
at roughly 300 KB and floats.

**MUST** reject any block above `50 · free_limit`, so one miner cannot make the chain
un-downloadable.

---

## 5. Reward

**AUTHORITATIVE: tail emission, a treasury slice, and no premine.**

| Parameter | Value | Note |
|---|---|---|
| Initial block reward | 20 units | placeholder; see 5.1 |
| Emission curve | smooth decrease over ~2 years | no halving cliffs |
| **Tail emission** | **0.6 units/block, forever** | the security budget does not decay to zero |
| Treasury slice | 10% of every block | funds the "useful work" programme |
| Coinbase maturity | **100 blocks** | a reward from a reorged-out block is not spendable |
| Premine | **none** | |

### 5.1 The number is not the decision

`reward × blocks/year × price` is the annual security budget. For a coin with no users
that product is zero, so any figure is arbitrary at launch. What matters is the **shape**:

- **Tail emission is mandatory.** A fixed cap means the security budget decays to zero as
  fees fail to replace it, and a privacy coin's fees will be small. Monero added tail
  emission for exactly this reason.
- **No premine.** There is no technical justification for one here, and it is the single
  most damaging thing that can be done to a new coin's legitimacy.
- **The treasury slice is how the "useful contribution" gets funded** — a fraction of
  every block, auditable on-chain, rather than hidden in an allocation.

---

## 6. Fork choice

**AUTHORITATIVE: cumulative work, not height.**

- The tip is the block with the greatest sum of `difficulty` over its ancestry.
- Ties are broken by the hash with the lower numeric value, which is arbitrary but
  deterministic.
- A node MUST NOT reorganise deeper than `100` blocks without operator intervention, since
  that exceeds coinbase maturity and is a symptom rather than an event.
- The mempool MUST be re-admitted after a reorg, with transactions already in the new
  chain removed.

Height is not work. Two chains of equal height can have different total work, and a
height rule lets an attacker mine a low-difficulty fork cheaply.

---

## 7. What this specification does NOT decide

Every item here needs a peer-to-peer layer that does not exist. Writing parameters for
them now would be fiction.

| Item | Why it is blocked |
|---|---|
| Propagation delay, orphan rate | no network to measure |
| Whether 120 s survives measurement | depends on propagation |
| Mempool policy, fee market | needs competing miners |
| Peer discovery, sync, eclipse resistance | no p2p |
| Difficulty bootstrap (§3.5) | needs a launch decision, not a measurement |
| Consensus among *validating* nodes | our node validates; a network of them does not exist |
| Checkpointing / weak subjectivity | depends on the above |

---

## 8. What would change this document

1. **A measured orphan rate.** If 120 s produces more than ~2% orphans at realistic
   propagation, the block time should rise, not fall.
2. **Proof size reduction or aggregation.** If a transaction drops below 5 KB, the
   throughput ceiling moves by an order of magnitude and §1 stops binding.
3. **A decision on amounts.** Range proofs add bytes to every transaction, which feeds
   straight back into §1.
4. **Audit findings.** Any of the above numbers is a starting position, not a result.

---

## Related

- [`PERFORMANCE.md`](../PERFORMANCE.md) — where the per-transaction figures come from
- [`SECURITY-NOTES.md`](../SECURITY-NOTES.md) — what the security numbers do and do not mean
- `vault/Amount Confidentiality.md` — the other thing that adds bytes to a transaction
- `vault/Status and Honest Limitations.md` — the wider gap list
