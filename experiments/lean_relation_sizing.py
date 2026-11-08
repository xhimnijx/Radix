"""Static cost model for the "lean" transaction relation (M3 experiment).

Why this exists
---------------
The RDXL64P1 profile cannot run: its resource preflight computes a 4.77 GiB
randomized-matrix + low-degree-extension (LDE) payload and refuses to start
against a 1 GiB cross-target cap. Before spending weeks implementing a smaller
circuit, we need a decision-grade estimate of whether removing the in-circuit
KDF/AEAD work is *sufficient* to fit the project's own device budget.

This script does not build a trace or a proof. It applies the same dimension
arithmetic as `rdxl_resource_report()` to two parameter sets and converts the
LDE floor into a predicted single-proof peak using the ratio observed in the two
measured component runs. Run it from the repository root:

    python -m experiments.lean_relation_sizing

Numbers are only as good as the inputs below; every one is annotated with its
source so a reviewer can challenge it individually.
"""

from __future__ import annotations

from dataclasses import dataclass

FIELD_BYTES = 4          # BabyBear base-field element
EXT_FIELD_BYTES = 16     # BinomialExtensionField<BabyBear, 4>
LOG_BLOWUP = 2           # pinned `new_testing_zk` / HidingFriPcs test profile
ZK_RANDOM_CODEWORDS = 4  # Pcs::new(..., 4, ...)
DESKTOP_CAP = 4 * 1024**3
MOBILE_CAP = 1 * 1024**3

#: Peak / LDE ratio. Two regimes, both measured on 2026-11-08 with
#: `experiments/measure_rust_test.ps1` against prebuilt release test binaries:
#:
#:   single focused proof (RDXZ64P1, path only):
#:       LDE 661,323,776 B, peak 2,669,219,840 B -> 4.04x
#:   composed test that builds several proofs (RDXK64P1):
#:       LDE 985,006,080 B, peak 9,242,767,360 B -> 9.39x
#:
#: A wallet proves exactly one transaction, so 4.0x is the relevant figure and
#: 9.5x is the conservative planning bound. Budget checks report both.
SINGLE_PROOF_MULTIPLIER = 4.0
PLANNING_MULTIPLIER = 9.5
EMPIRICAL_PEAK_PER_LDE = PLANNING_MULTIPLIER

#: Width banks that exist only to prove KDF/AEAD consistency. Each entry is a
#: slice that disappears in the lean relation. Source: depth64_path_opening.rs
#: constants, post key-schedule revert (width 15,629).
REMOVED_BANKS = {
    "input KDF source bytes (KEM ct + ss)": 64 + 1088,
    "input KDF derived key": 32,
    "input AEAD nonce + ciphertext witness": 12 + 156,
    "input note rho/randomness witness": 128,
    "AES-256 key schedule + stage/index bits": 1920 + 1 + 4,
    "AES-256 CTR block banks (8x128) + 16 S-box slices": 8 * 128 + 16 * 48 + 1 + 4 + 4,
    "output KDF secret + mode + bit booleanity": 32 + 1 + 256,
    "input KDF stage/index bits": 1 + 4,
}

#: Active-row accounting from TRANSACTION-PROOF-PROTOTYPE-SCOPE.md ("RDXL
#: row-domain reduction threshold"): path 3072, source leaf 240, note 48,
#: spend/owner 48, nullifier 48, output note 48, output leaf 240, KDF 216 x2,
#: AES stages 148 x2 -> 4,472 at the 156-byte profile, 4,568 at the maximum.
RDXL_ACTIVE_ROWS = 4_472
RDXL_ACTIVE_ROWS_MAX = 4_568
KDF_AND_AES_ROWS = 216 + 216 + 148 + 148


@dataclass(frozen=True)
class Profile:
    name: str
    active_rows: int
    width: int

    @property
    def rows(self) -> int:
        """Next power of two at least this large (the STARK trace domain)."""
        rows = 1
        while rows < self.active_rows:
            rows <<= 1
        return rows

    @property
    def trace_bytes(self) -> int:
        return self.rows * self.width * FIELD_BYTES

    @property
    def randomized_bytes(self) -> int:
        return 2 * self.rows * (self.width + ZK_RANDOM_CODEWORDS) * FIELD_BYTES

    @property
    def lde_bytes(self) -> int:
        rows = 2 * self.rows * (1 << LOG_BLOWUP)
        return rows * (self.width + ZK_RANDOM_CODEWORDS) * FIELD_BYTES

    @property
    def overlap_bytes(self) -> int:
        return self.randomized_bytes + self.lde_bytes

    @property
    def predicted_peak_bytes(self) -> int:
        return int(self.lde_bytes * EMPIRICAL_PEAK_PER_LDE)

    @property
    def single_proof_peak_bytes(self) -> int:
        return int(self.lde_bytes * SINGLE_PROOF_MULTIPLIER)

    def describe(self) -> str:
        return (
            f"{self.name}: active={self.active_rows:,} rows={self.rows:,} "
            f"width={self.width:,} trace={self.trace_bytes/1e6:,.0f} MB "
            f"LDE={self.lde_bytes/2**30:,.2f} GiB "
            f"overlap={self.overlap_bytes/2**30:,.2f} GiB "
            f"peak@4x={self.single_proof_peak_bytes/2**30:,.1f} GiB "
            f"peak@9.5x={self.predicted_peak_bytes/2**30:,.1f} GiB"
        )


def max_width_for(cap_bytes: int, rows: int) -> int:
    """Widest trace that keeps the predicted peak under ``cap_bytes``."""
    lde_budget = cap_bytes / EMPIRICAL_PEAK_PER_LDE
    # LDE = rows * (1<<LOG_BLOWUP) * 2 * (width+4) * 4
    per_column = rows * (1 << LOG_BLOWUP) * 2 * FIELD_BYTES
    return int(lde_budget // per_column) - ZK_RANDOM_CODEWORDS


def main() -> int:
    rdxl = Profile("R-fat (current RDXL64P1)", RDXL_ACTIVE_ROWS_MAX, 15_629)
    removed = sum(REMOVED_BANKS.values())
    lean_width = rdxl.width - removed
    lean = Profile("R-lean (no KDF/AEAD)", RDXL_ACTIVE_ROWS_MAX - KDF_AND_AES_ROWS, lean_width)

    # A depth-64 path is witnessed bit-sliced: 4,096 current-node bits plus
    # 4,096 sibling bits, kept live across every row for the transition
    # constraints. Packing each 64-byte digest into 32 x 16-bit limbs (384
    # columns instead of 8,192) and expanding to bits only inside the active
    # Keccak rows is the single largest remaining structural win. It is an
    # estimate: it needs a witness-layout refactor and a fresh column-lifetime
    # audit before it is real.
    path_bits = 2 * 4096
    path_limbs = 2 * (64 // 2 * 2)  # 32 limbs * 2 bytes * 2 digests
    packed_width = lean_width - (path_bits - path_limbs)
    packed = Profile(
        "R-lean+packed path", RDXL_ACTIVE_ROWS_MAX - KDF_AND_AES_ROWS, packed_width
    )

    # The floor: the smallest profile the harness ever measured, path-only.
    floor = Profile("RDXZ64P1 path-only floor", 3_072, 5_043)

    print("Static cost model for the Candidate-A transaction relation")
    print(f"field={FIELD_BYTES}B extension={EXT_FIELD_BYTES}B blowup=2^"
          f"{LOG_BLOWUP} zk_codewords={ZK_RANDOM_CODEWORDS}")
    print(f"empirical peak/LDE multiplier: {SINGLE_PROOF_MULTIPLIER}x single proof, "
          f"{PLANNING_MULTIPLIER}x conservative planning (measured 2026-11-08)")
    print()

    print("Removed column banks in the lean relation:")
    for label, columns in REMOVED_BANKS.items():
        print(f"  {columns:>6,}  {label}")
    print(f"  {removed:>6,}  total removed ({removed / rdxl.width:.0%} of width)")
    print()

    for profile in (rdxl, lean, packed, floor):
        print(profile.describe())
    print()

    print("Budget checks (predicted peak, see LEAN-RELATION.md for caveats):")
    for profile in (rdxl, lean, packed, floor):
        single = profile.single_proof_peak_bytes
        conservative = profile.predicted_peak_bytes
        verdict = (
            "FITS desktop"
            if conservative <= DESKTOP_CAP
            else ("fits desktop only at 4x" if single <= DESKTOP_CAP else "EXCEEDS desktop")
        )
        mobile = (
            "fits mobile at 4x"
            if single <= MOBILE_CAP
            else f"{single / MOBILE_CAP:.1f}x mobile cap at 4x"
        )
        print(
            f"  {profile.name}: {verdict} "
            f"({single / DESKTOP_CAP:.1f}x cap at 4x, {conservative / DESKTOP_CAP:.1f}x at 9.5x); "
            f"{mobile}"
        )
    print()

    print("Sensitivity: predicted peak under different peak/LDE multipliers")
    print(f"  {'profile':28s} " + " ".join(f"{m:>7}x" for m in (4.0, 5.0, 7.5, 9.5, 12.0)))
    for profile in (rdxl, lean, packed, floor):
        cells = " ".join(
            f"{profile.lde_bytes * m / 2**30:7.1f}" for m in (4.0, 5.0, 7.5, 9.5, 12.0)
        )
        print(f"  {profile.name:28s} {cells}   (GiB)")
    print()

    print("Width ceilings implied by the empirical multiplier:")
    for label, cap in (("desktop 4 GiB", DESKTOP_CAP), ("mobile 1 GiB", MOBILE_CAP)):
        for rows in (4_096, 2_048, 1_024):
            print(f"  {label:14s} rows={rows:5,} -> width <= {max_width_for(cap, rows):,}")
    print()

    print(f"Lean width is {lean_width:,} columns; packed estimate is {packed_width:,}.")
    print(f"Desktop allows {max_width_for(DESKTOP_CAP, lean.rows):,} at 4,096 rows; "
          f"mobile allows {max_width_for(MOBILE_CAP, lean.rows):,}.")
    print("Verdict: lean alone is necessary but insufficient; packing the path")
    print("witness is the next lever. See LEAN-RELATION.md for the decision record.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
