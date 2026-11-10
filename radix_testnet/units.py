"""D4: the unit, the decimals and the supply cap, in exactly one place.

The plan requires a frozen constant table that lives in one code location. This is it. Everything
else imports from here, so a display bug and a consensus bug cannot disagree about what an atom is.

The cap is not a monetary preference; it is a **soundness bound**. The trace-paired balance argument
is a congruence modulo `q`, so it yields integer balance only while every total stays below `q/2`.
Changing these numbers is changing what the balance proof means, which is why they are here with the
derivation rather than scattered through the code.
"""

from __future__ import annotations

from radix_core.candidate_b.lattice.params import SMILE

#: Atoms in one displayable unit. Two decimal places.
ATOMS_PER_UNIT = 100

#: Decimals to show. `ATOMS_PER_UNIT` must be `10 ** DECIMALS`.
DECIMALS = 2

#: The total supply cap, in atoms. 5,701,000 units.
#:
#: Derived, not chosen: the emission schedule totals 570,093,820 atoms (measured, see
#: `tests/test_testnet_supply_cap.py`), and the balance argument requires the whole supply to sit
#: below `q / 2`. This rounds the schedule total up and leaves 3.77x of headroom.
SUPPLY_CAP_ATOMS = 570_100_000

#: The modulus bound the cap exists to respect.
MAX_SOUND_ATOMS = SMILE.modulus // 2


def units_of(atoms: int) -> float:
    """Convert atoms to displayable units."""
    return atoms / ATOMS_PER_UNIT


def atoms_of(units: float) -> int:
    """Convert displayable units to atoms, refusing a value that is not a whole atom."""
    scaled = round(units * ATOMS_PER_UNIT)
    if abs(units * ATOMS_PER_UNIT - scaled) > 1e-6:
        raise ValueError(f"{units} units is not a whole number of atoms")
    return scaled


def format_atoms(atoms: int) -> str:
    """`12345` -> `"123.45"`, without a float in the path."""
    sign = "-" if atoms < 0 else ""
    whole, fraction = divmod(abs(int(atoms)), ATOMS_PER_UNIT)
    return f"{sign}{whole}.{fraction:0{DECIMALS}d}"
