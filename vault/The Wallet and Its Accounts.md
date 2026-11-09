---
title: The Wallet and Its Accounts
tags: [wallet, testnet]
---

# The wallet and its accounts

`radix_testnet/wallet.py`. Four accounts from one seed, a send flow, and one important
constraint that comes straight from the cryptography.

## Why accounts, not notes

Two facts force the design:

1. **A ring signature hides which output it spends**, so the chain cannot remove an
   output ([[The Chain]]).
2. **The linkable tag is a function of the secret**: `T = A'·s`. One keypair therefore
   owns one tag, and spending once **burns that tag**.

So an account — one keypair — is spendable exactly once, and change must go to a
*different* account. That is not a harness shortcut; it is what per-key linkability
means.

> [!warning] The real design is one key per output — and it is unsolved here
> A production wallet gives every output its own keypair via one-time addressing, so
> each note has its own tag. That needs a key exchange the scheme does not provide yet
> and is B2 work, not built here. The obstacle is written up in
> [[One-Time Addressing]]: the natural construction needs a Diffie–Hellman-like
> operation that lattices do not have.

## Structure

```python
@dataclass
class Account:
    index: int
    secret: tuple     # small coefficients
    public: tuple     # A · secret
    notes: list[Output]

@dataclass
class Wallet:
    seed: bytes
    parameters: RS.Parameters
    accounts: list[Account]   # 4, derived deterministically
```

`__post_init__` derives each account with `RS.keygen(parameters, rng(seed ‖ index))`, so
the same seed always gives the same four keys.

## Scanning

`Wallet.scan(chain)` walks the chain's outputs and keeps those whose key equals an
account's public key, **excluding accounts whose tag is already spent**:

```python
if tag_of(account.secret, parameters) in chain.spent_tags:
    continue
```

That single line is why a spent account shows a zero balance even though its output is
still on the chain.

## Sending

`build_spend(chain, recipient, amount, fee, change_account=None)`:

1. pick an account with an unspent note large enough;
2. build outputs: the payment, plus change to the **next** account;
3. take a ring: `chain.ring_for(account.public, rng)` → 1024 indices;
4. sign a tagged spend (Python or Rust, depending on the backend — [[The Rust Backend Seam]]).

## Addresses

An address is `rtx1` followed by **base64url of the 2048-byte public key**: 2,735
characters.

Why not hex? A QR code in byte mode holds at most 2,953 bytes; hex doubles 2048 to
4,096 and **cannot fit**. Base64url fits at error-correction level L, which the app
uses. The receive screen shows a truncated address with Copy and Show-full because
2,735 characters in a card is unusable.

## Amounts

Amounts are plain integers on outputs. There are **no amount commitments, no range
proofs and no conservation proof** — the harness trusts the stated values. That is B2
work. It is listed in [[Status and Honest Limitations]].

## Key storage

There is **no encrypted keystore**, deliberately: the faucet seed is a public constant
printed in the source, so encrypting it would imply a security property the harness
does not have. `radix_core/wallet_keystore.py` contains sealed-key machinery for a
future real wallet.

## Next

[[The Node and Miner]], then [[The Wire Format]].
