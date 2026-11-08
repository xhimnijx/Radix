# Measurements

**Date:** 2026-11-08 · **Host:** Windows 11 Pro, Intel Core i7-1185G7 (4C/8T), 15.7 GiB RAM,
rustc 1.99.1 · **Method:** `experiments/measure_rust_test.ps1`.

This file records what was actually executed and observed, as opposed to modelled.
Everything else in the repository that says "predicted" comes from
`experiments/lean_relation_sizing.py`, which is calibrated on the numbers below.

## Why these are the measurements available

The local toolchain cannot link a Rust binary: the MSVC linker (`link.exe`) is not
installed and no MinGW `gcc`/`dlltool` is present. `cargo check` and
`cargo check --tests` type-check the whole crate (exit 0), but nothing new can be
built or run here.

However, `proof_harness/target/release/deps/` contains a **prebuilt release test
binary from 2026-11-01** (`radix_proof_harness-a6743722e416b94c.exe`, 10.0 MB). It
predates the `#[ignore]` attributes and the RDXL AES work, but it contains the
depth-64 component provers and runs on this machine. Running it is a real
measurement of the Plonky3 prover on this hardware; it is *not* a measurement of the
current source tree.

## Procedure

```
& .\experiments\measure_rust_test.ps1 `
    -Binary "proof_harness\target\release\deps\radix_proof_harness-a6743722e416b94c.exe" `
    -TestName "<filter>" -TimeoutSeconds 900
```

The script launches one test in its own process, polls `PeakWorkingSet64` every
100 ms (the OS high-water mark), and reports elapsed wall time. One test per
process, so the peak belongs to that test's work.

## Results

| # | Test (profile) | Dimensions | LDE | Elapsed | Peak working set | Peak / LDE |
|---|---|---|---:|---:|---:|---:|
| 1 | `proves_and_verifies_private_depth64_path` (`RDXZ64P1`, path only) | 4,096 x 5,043 | 661,323,776 B (0.62 GiB) | **17.91 s** | **2,669,219,840 B (2.49 GiB)** | **4.04x** |
| 2 | `source_key_note_nullifier_profile_...` (`RDXK64P1`, spend key + owner + note + nullifier + path) | 4,096 x 7,512 | 985,006,080 B (0.92 GiB) | **60.01 s** | **9,242,767,360 B (8.61 GiB)** | **9.39x** |

Both runs reported `test result: ok`, one test each, no other tests executing.

## What the two ratios mean

The spread (4.0x vs 9.4x) is not noise; it is a difference in **how many proofs the
test builds**.

- Test 1 builds and verifies a single proof, then exits. 4.0x is the honest
  single-proof figure and is the relevant one for a wallet: a wallet proves one
  transaction at a time.
- Test 2 is a composed adversarial test: it builds the valid proof and then several
  mutated proofs (changed sibling, wrong statement, manipulated witness) in the same
  process. Each mutation allocates again before the previous allocation is dropped,
  so the process high-water mark reflects *N proofs*, not one. Later revisions added
  trace reuse for exactly this reason ("the four mutation scans now reuse the same
  trace"), which is why the project's own published peaks (~9.5 GiB) sit near this
  figure rather than the single-proof one.

So: **4.0x for one wallet proof, ~9.4x for a multi-proof test process.** The cost
model reports both; the conservative 9.5x is used for planning, 4.0x for the
single-proof column.

## Implications for the decision record

Using the measured single-proof ratio (4.0x) instead of the planning ratio (9.5x)
changes the R-lean verdict from "2.9x over" to "1.2x over" and moves the packed
profile to roughly **1.0 GiB** predicted - at the mobile cap and comfortably inside
the desktop cap. That is why "pack the path witness and measure" is the next
milestone rather than "abandon desktop". See `LEAN-RELATION.md` Part B.

Two measured facts worth keeping:

- The **path-only** proof (the harness's own floor) uses 2.49 GiB and 17.9 s on
  this laptop. Any design that adds note, nullifier, output, balance and KEM on top
  of that has to regain that budget, not merely fit within it.
- A composed profile with none of the output side reaches 8.61 GiB and 60 s. That
  is already 2.2x the desktop cap, and it is the reason the monolithic route is
  judged NO-GO as structured.

## Limitations (read before quoting these numbers)

1. **Pre-revert build.** The binary predates the AES key-schedule revert and the
   RDXL output/KDF work. It measures RDXZ64P1 and RDXK64P1, not RDXL64P1, and not
   the packed-path layout proposed in `LEAN-RELATION.md`.
2. **One run each.** No repetition, no CPU pinning, no thermal control; treat the
   times as +-20 % and the memory figures as high-water marks that exclude any
   allocation already freed before the 100 ms sample (peaks between samples can be
   missed).
3. **Test-process peaks, not isolated proving calls.** `PeakWorkingSet64` covers
   the whole process, including trace construction, proof encoding, verification,
   and the test harness.
4. **Not the production configuration.** The build uses the pinned test FRI profile
   (2 queries, blowup 2). A production profile (>= 100 queries, blowup >= 3)
   increases both proof size and prover work; memory predictions here are a floor
   for that configuration, not an estimate of it.
5. **Local host only.** Numbers are for this i7-1185G7 / 15.7 GiB machine; a phone
   was never measured and cannot be measured with this harness.

## Reproducing elsewhere

On a machine with a working linker:

```powershell
cd proof_harness
cargo test --release -- --ignored --exact `
  depth64_path_opening::tests::proves_and_verifies_private_depth64_path --nocapture
```

and sample the process peak with `experiments/measure_rust_test.ps1` pointed at the
newly built `target/release/deps/radix_proof_harness-*.exe`. That produces the
number the M3 pass rule actually requires: a *current-source* single-proof peak.
