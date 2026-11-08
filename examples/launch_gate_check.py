"""Print the launch-gate state and the exact parameter hash a review must cover.

Run from the repository root:

    python -m examples.launch_gate_check

Exits 0 always: this is a status command, not a launch. It never opens the gate.
"""

from __future__ import annotations

import sys

from radix_core.launch import (
    DEFAULT_GATE,
    MAINNET_PARAMETERS,
    MAINNET_SWITCH,
    NetworkMode,
    RESEARCH_PARAMETERS,
    TESTNET_PARAMETERS,
)


def _describe(label: str, gate) -> None:
    parameters = gate.parameters
    print(f"{label}")
    print(f"  mode:               {parameters.mode.value}")
    print(f"  proof profile:      {parameters.proof_profile.name}")
    print(f"  production-grade:   {parameters.proof_profile.is_production_grade()}")
    print(f"  genesis finalised:  {parameters.genesis_hash != bytes(32)}")
    print(f"  discovery:          {parameters.recipient_discovery}")
    print(f"  parameters hash:    {parameters.parameters_hash().hex()}")
    print(f"  gate open:          {gate.is_open}")
    reasons = gate.describe_refusals()
    if reasons:
        print("  refusal reasons:")
        for reason in reasons:
            print(f"    - {reason}")
    print()


def main(argv: list[str]) -> int:
    if argv:
        print("launch_gate_check takes no arguments", file=sys.stderr)
        return 2
    print("Radix launch gate status (nothing here authorises a launch)\n")
    _describe("active default gate", DEFAULT_GATE)
    _describe("mainnet switch", MAINNET_SWITCH)
    print("mode summary:")
    for label, parameters in (
        ("research", RESEARCH_PARAMETERS),
        ("testnet", TESTNET_PARAMETERS),
        ("mainnet", MAINNET_PARAMETERS),
    ):
        print(
            f"  {label:9s} mode={parameters.mode.value:8s} "
            f"profile={parameters.proof_profile.name}"
        )
    print()
    print("Mainnet remains locked until the switch in MAINNET-SWITCHOVER.md is opened")
    print("by a reviewed commit plus signed review attestations. This command cannot")
    print("open it, and neither can any flag or environment variable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
