"""Static cost model for the Candidate-A transaction relation (M3 experiment).

Revised 2026-11-08 after the Rust suite finally executed. Two earlier inputs were
wrong and are corrected here:

* The actual RDXL trace width is 14,173, not the 14,477 or 15,629 earlier drafts
  assumed. `cargo run -- rdxl-resource-report` printed 8192x14173 after the
  key-schedule revert, and the suite now pins that.
* The path witness is 512 current-state bits plus 512 sibling bits, not 8,192.
  Packing the sibling digest into 16-bit limbs therefore saves 480 columns, not
  about 7,808. The dominant width is the 2,937-column Keccak AIR plus the KDF and
  AEAD banks.

Run from the repository root:

    python -m experiments.lean_relation_sizing
"""

from __future__ import annotations

from dataclasses import dataclass

FIELD_BYTES = 4
ZK_RANDOM_CODEWORDS = 4
DESKTOP_CAP = 4 * 1024**3
MOBILE_CAP = 1 * 1024**3

SINGLE_PROOF_MULTIPLIER = 4.0
PLANNING_MULTIPLIER = 9.5

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

SIBLING_PACKING_SAVING = 512 - 32

KECCAK_WIDTH = 2_937
ABSORB_WIDTH = 288
ALGEBRAIC_HASH_WIDTH = 300
ALGEBRAIC_ABSORB_WIDTH = 16
ALGEBRAIC_SAVING = (KECCAK_WIDTH - ALGEBRAIC_HASH_WIDTH) + (ABSORB_WIDTH - ALGEBRAIC_ABSORB_WIDTH)

RDXL_ACTIVE_ROWS_MAX = 4_568
KDF_AND_AES_ROWS = 216 + 216 + 148 + 148


@dataclass(frozen=True)
class Profile:
    name: str
    active_rows: int
    width: int
    log_blowup: int = 2

    @property
    def rows(self) -> int:
        rows = 1
        while rows < self.active_rows:
            rows <<= 1
        return rows

    @property
    def lde_bytes(self) -> int:
        rows = 2 * self.rows * (1 << self.log_blowup)
        return rows * (self.width + ZK_RANDOM_CODEWORDS) * FIELD_BYTES

    def peak(self, multiplier: float) -> int:
        return int(self.lde_bytes * multiplier)

    def line(self, multiplier: float) -> str:
        return (
            f"{self.name:36s} rows={self.rows:5,} width={self.width:6,} "
            f"LDE={self.lde_bytes / 2**30:5.2f} GiB "
            f"peak@{multiplier:g}x={self.peak(multiplier) / 2**30:5.1f} GiB"
        )


def max_width(cap_bytes: int, rows: int, log_blowup: int) -> int:
    lde_budget = cap_bytes / SINGLE_PROOF_MULTIPLIER
    per_column = 2 * rows * (1 << log_blowup) * FIELD_BYTES
    return int(lde_budget // per_column) - ZK_RANDOM_CODEWORDS


def main() -> int:
    fat_width = 14_173
    removed = sum(REMOVED_BANKS.values())
    lean_width = fat_width - removed
    packed_width = lean_width - SIBLING_PACKING_SAVING
    algebraic_width = packed_width - ALGEBRAIC_SAVING

    base = [
        Profile("R-fat (RDXL64P1 today)", RDXL_ACTIVE_ROWS_MAX, fat_width),
        Profile("R-lean (no KDF/AEAD)", RDXL_ACTIVE_ROWS_MAX - KDF_AND_AES_ROWS, lean_width),
        Profile("R-lean + packed sibling", RDXL_ACTIVE_ROWS_MAX - KDF_AND_AES_ROWS, packed_width),
        Profile("R-lean + packed + algebraic hash", RDXL_ACTIVE_ROWS_MAX - KDF_AND_AES_ROWS, algebraic_width),
        Profile("RDXZ64P1 path-only floor", 3_072, 5_043),
    ]

    print("Candidate-A relation cost model (corrected after the Rust suite ran)")
    print(
        f"field={FIELD_BYTES}B zk_codewords={ZK_RANDOM_CODEWORDS} multipliers: "
        f"{SINGLE_PROOF_MULTIPLIER}x single proof / {PLANNING_MULTIPLIER}x planning"
    )
    print()
    print(f"removed for lean: {removed:,} columns (fat {fat_width:,} to lean {lean_width:,})")
    print(f"sibling packing: -{SIBLING_PACKING_SAVING} gives {packed_width:,}")
    print(f"algebraic hash (counterfactual): -{ALGEBRAIC_SAVING} gives {algebraic_width:,}")
    print()

    for blowup in (2, 3):
        label = "pinned test profile" if blowup == 2 else "production blowup"
        print(f"== log_blowup = {blowup} ({label}) ==")
        configured_profiles = [
            Profile(p.name, p.active_rows, p.width, blowup) for p in base
        ]
        for profile in configured_profiles:
            print("  " + profile.line(SINGLE_PROOF_MULTIPLIER))
        print()
        for profile in configured_profiles:
            single = profile.peak(SINGLE_PROOF_MULTIPLIER)
            conservative = profile.peak(PLANNING_MULTIPLIER)
            desktop = (
                "FITS"
                if conservative <= DESKTOP_CAP
                else f"{conservative / DESKTOP_CAP:.1f}x over"
            )
            phone = (
                "FITS"
                if single <= MOBILE_CAP
                else f"{single / MOBILE_CAP:.1f}x over"
            )
            print(
                f"  {profile.name:36s} desktop: {desktop} "
                f"(single proof {single / DESKTOP_CAP:.2f}x cap); phone: {phone}"
            )
        print()

    print("Width ceilings at production blowup (log_blowup=3), single-proof 4x:")
    for label, cap in (("desktop 4 GiB", DESKTOP_CAP), ("phone 1 GiB", MOBILE_CAP)):
        for rows in (4_096, 2_048, 1_024):
            print(f"  {label:13s} rows={rows:5,} -> width at most {max_width(cap, rows, 3):,}")
    print()
    print("Reading: width is dominated by Keccak (2,937) plus the KDF/AEAD banks")
    print("(5,500), not by the path witness (512+512). Even lean+packed+algebraic at")
    print("4,096 rows cannot reach the phone cap, so a single monolithic AIR is the")
    print("wrong shape for a 1 GiB device. See ARCHITECTURE-DECISION.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
