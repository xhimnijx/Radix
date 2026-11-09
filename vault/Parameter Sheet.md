---
title: Parameter Sheet
tags: [reference]
---

# Parameter sheet

A one-page reference. Nothing here is derived at runtime; all values are fixed in
`params.py` / `statement.rs`.

## Manifest

```
q               4,294,966,337       prime, q ≡ 1 (mod 64), q ≢ 1 (mod 128)
d               128                 ring degree
l               32                  subring dimension (slots per polynomial)
k               4                   matrix rows
ell             13                  matrix columns
kappa           10                  B_0 rows / commitment head
lambda          10                  extra mask components
mu              5                   secret coefficient bound
k'              4                   tag rows (this project)
m               2                   recursion depth, ring = 32^2 = 1024
```

## Derived

```
W (untagged)    29     = kappa + lambda + k   + 2m + 1
W (tagged)      33     = kappa + lambda + (k+k') + 2m + 1
commitments     19     = kappa + k   + 2m + 1        (23 tagged)
proof bytes     32,512 (36,608 tagged) + 2,048 tag
```

## Masking (measured, not chosen)

```
coefficient var 627
T_z             1701     99th percentile, W = 33
T_z'            1081     99th percentile, ell = 13
s = 1.567 T     2670 (2^11.4) for z,  1684 (2^10.7) for z'
M               1.225    = sqrt(3/2)
attempts        2M^2 ≈ 3 per rejection point; measured 9.75 total
beta            2^17.9   = s sqrt(2Wd)
beta'           2^16.6   = s' sqrt(2 ell d)
```

## Security-relevant

```
challenge-diff   ~2^-123  (field regime; was ~2^-24.4 split)
unit check       ~2^-123
M-SIS target A   2 beta'  = 2^17.6
M-SIS target B0  8 d beta = 2^27.9
reachable (A)    2^21.2   at delta = 1.0042
reachable (B0)   2^31.7
margin           ~3.6 / ~3.8 bits   <- root-Hermite heuristic, NOT a security level
```

## Performance (measured)

```
prove           496 ms     Rust, release, depth 2
verify          110 ms     Rust
python prove    1-2 min
python verify   20-38 s
ring mul        20.1 us
```

## Status flags

```
MODULUS_FROM_PAPER   False      this q is this project's choice
mainnet gate         closed     launch.py requires a signed audit manifest
estimator run        none       no security level may be claimed
```

See [[The Parameters and Where Every Number Comes From]] for provenance and
[[Status and Honest Limitations]] for what the gaps mean.
