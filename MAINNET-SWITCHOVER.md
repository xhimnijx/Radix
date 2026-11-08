# Mainnet switchover runbook

**Applies to:** the transition from `RESEARCH`/`TESTNET` to a network that carries
value. **Status:** the switch is **closed**. This document is the procedure a
reviewed change would follow; it does not authorise a launch.

---

## 1. What "one switch" means, precisely

There is exactly one place a launch changes trust, and exactly one place it changes
values:

| Switch | File | What one reviewed edit does |
|---|---|---|
| Trust anchors | `radix_core/launch.py` → `MAINNET_SWITCH.trusted_reviewer_keys` | Adds the independent reviewers' Ed25519 public keys. Empty tuple = locked. |
| Frozen values | `radix_core/launch.py` → `MAINNET_PARAMETERS` | Sets a finalised genesis and a reviewed `recipient_discovery` value. |

No environment variable, CLI flag, configuration file, or network message can open
the gate. `open_launch_gate()` is the only function that returns mainnet
parameters, and it refuses while any condition in
`LaunchGate.describe_refusals()` is unmet.

The parameter hash is the unit of review:

```powershell
python -m examples.launch_gate_check
# prints: parameters hash: <hex>   for each configuration
```

That hash is computed over `LaunchParameters.canonical_bytes()`, which contains
every consensus field (mode, version, chain id, genesis, block interval, per-block
item and payload caps, aggregate fee cap, anchor window, proof profile, memo
profile, discovery construction). Changing any one of them changes the hash and
therefore invalidates every previous attestation.

---

## 2. Preconditions (all must be true before touching the switch)

1. Two independent cryptographic reviews covering **soundness, zero-knowledge,
   QROM, consensus, and recipient privacy** — see `archive/candidate-a/AUDIT-PACKET.md`.
2. A complete transaction relation that proves on the reference hardware class
   (see `archive/candidate-a/PLAN.md` M3). Today it does not.
3. A production FRI parameter set (the gate requires `log_blowup ≥ 3`,
   `num_queries ≥ 100`, `query PoW ≥ 16`). Today the provers use a 2-query test
   config and are refused by the gate.
4. A selected, reviewed recipient-discovery construction. Today it is
   `unresolved-requires-review`, which the gate refuses.
5. A generated genesis block whose hash is recorded, plus a published genesis
   description and supply audit.
6. Qualified legal review for the intended jurisdictions (Gate 0 exit item).
7. An incident-response plan and a funded bug bounty.

If any item is missing, the correct action is **not** to edit the gate.

---

## 3. Switchover procedure

### Step 1 — freeze the candidate parameter block

Edit only `MAINNET_PARAMETERS` values that still differ from the reviewed design.
Run:

```powershell
python -m examples.launch_gate_check
```

Record the printed `parameters hash` in the launch record. From this moment the
block is frozen; any further change restarts review.

### Step 2 — generate and finalise genesis

```python
from radix_core.launch import MAINNET_PARAMETERS, finalize_genesis
parameters = finalize_genesis(MAINNET_PARAMETERS, genesis_block_hash)
assert parameters.genesis_hash != bytes(32)
```

`finalize_genesis` refuses the pending sentinel and any non-32-byte value. Publish
the genesis construction script and its output hash before mining starts.

### Step 3 — resolve recipient discovery

Set `recipient_discovery` to one of the values in `REVIEWED_DISCOVERY`
(`pq-stealth-address-v1`, `pq-stealth-address-reviewed`, or a reviewed
`ml-kem-768-static` value). The gate accepts only those; a free-form string is
refused, so the P0 privacy blocker cannot be waved through by editing wording.

### Step 4 — collect attestations

Each reviewer signs the manifest payload with an Ed25519 key:

```python
from radix_core.launch import AuditManifest, Attestation, REQUIRED_MAINNET_SCOPES, MAINNET_PARAMETERS
from hashlib import sha256

parameters_hash = <frozen hash>
manifest = AuditManifest(
    parameters_hash=parameters_hash,
    scopes=tuple(sorted(REQUIRED_MAINNET_SCOPES)),
    issued_at=<unix seconds>,
    attestations=(Attestation("<reviewer>", sha256(pubkey).digest(), b"\x00" * 64),),
)
payload = manifest.signed_payload()          # sign these exact bytes
# each reviewer returns: (name, sha256(pubkey).digest(), ed25519_sign(payload))
```

Scopes must include `soundness`, `zero-knowledge`, `qrom`, `consensus`, and
`recipient-privacy`. A missing scope is refused by name.

### Step 5 — open the gate

In one reviewed commit:

1. Add the reviewer public keys to `MAINNET_SWITCH.trusted_reviewer_keys`.
2. Commit the finalised `MAINNET_PARAMETERS` block.
3. Commit the signed manifest with the launch record.

Then verify:

```powershell
python -c "from radix_core.launch import MAINNET_SWITCH; print(MAINNET_SWITCH.describe_refusals())"
python -m examples.launch_gate_check
```

Both must report no refusal reasons. `MAINNET_SWITCH.is_open` must be `True`.

### Step 6 — independent operator verification

A second, unaffiliated operator must, from a clean checkout:

1. Recompute `MAINNET_PARAMETERS.parameters_hash()` and confirm it matches the
   published value.
2. Verify every attestation signature against the published reviewer keys.
3. Confirm `describe_refusals() == ()`.
4. Confirm the genesis hash matches the published genesis block.

If any check differs, the launch is aborted until resolved.

### Step 7 — post-launch

- Publish the parameter block, parameter hash, reviewer keys, attestations, genesis
  hash, release checksums, and reproducible-build instructions.
- Monitor proof rejection rate, block validation time, chain growth, and pool
  concentration against the pre-declared thresholds (`archive/candidate-a/PLAN.md` §3).
- Keep the pre-launch commit tagged; keep the previous release runnable.

---

## 4. Rollback

- The gate is a data/code artifact: reverting the commit to the research
  parameter block closes it again.
- A running network cannot be "un-launched" for its users; rollback means disabling
  a **new** release, not erasing a chain. That asymmetry is why the preconditions
  are strict.
- If a critical defect is found before genesis, revert and restart the review. If
  after launch, follow the incident-response plan; do not edit the gate to force a
  different parameter set under an old attestation.

---

## 5. What this does **not** do

- It does not make the cryptography safe. It makes an unsafe launch require a
  signature from someone qualified, over the exact bytes being launched.
- It does not substitute for a testnet. A gate can be opened for a network that
  has never run; that is an operator decision, and it should fail review.
- It cannot detect a reviewer who signs without reading. Independence and
  competence are social controls; the gate only makes a silent launch impossible.
