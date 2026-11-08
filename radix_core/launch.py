"""Launch gate: one switch, fail-closed, review-gated.

This module is the only sanctioned way to move the protocol from research to a
network that carries value. It does not certify safety; it makes the transition
*mechanical, explicit, and impossible to do quietly*:

* Every consensus-relevant value lives in one frozen ``LaunchParameters`` record.
  A mainnet launch does not edit constants scattered across the tree.
* ``MAINNET_SWITCH`` ships **closed**: its trusted-reviewer set is empty, so
  ``open_launch_gate`` refuses no matter what manifest is presented.
* The switch is a single reviewed edit: put one or more independent reviewer
  public keys in ``MAINNET_SWITCH.trusted_reviewer_keys`` (plus a finalised
  genesis and a reviewed recipient-discovery value), then supply the reviewers'
  signatures over the exact ``parameters_hash()``.
* Escalating the mode can only tighten. Mainnet requires the production proof
  profile, a finalised genesis, a reviewed discovery construction, and at least
  two distinct reviewer attestations covering every required scope.

Nothing here proves a cryptographer looked at the design. It proves that a
launch cannot happen until someone who did produced a signature over the exact
parameters being launched, and that the repository refuses by default.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import shake_frame
from .encoding import frame, u64

LAUNCH_PARAMETERS_TAG = "radix/launch-parameters/v1"
LAUNCH_PARAMETERS_HASH_TAG = "radix/launch-parameters-hash/v1"
AUDIT_MANIFEST_TAG = "radix/audit-manifest/v1"

PARAMETERS_HASH_BYTES = 32
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64

#: Sentinel meaning "no genesis has been generated for this parameter set yet".
PENDING_GENESIS = bytes(32)

#: A discovery construction that has not been selected/reviewed. A mainnet gate
#: refuses it, because recipient key privacy is an open P0 blocker today.
UNRESOLVED_DISCOVERY = "unresolved-requires-review"

#: Values a reviewed mainnet configuration may use for recipient discovery.
REVIEWED_DISCOVERY = frozenset(
    {
        "ml-kem-768-static-reviewed",
        "pq-stealth-address-v1",
        "pq-stealth-address-reviewed",
    }
)

REQUIRED_MAINNET_SCOPES = frozenset(
    {"soundness", "zero-knowledge", "qrom", "consensus", "recipient-privacy"}
)
MINIMUM_MAINNET_REVIEWERS = 2


class LaunchRefused(Exception):
    """The launch gate is closed, or the evidence presented does not open it."""


class NetworkMode(Enum):
    """What the parameters are allowed to be used for."""

    RESEARCH = "research"
    TESTNET = "testnet"
    MAINNET = "mainnet"


@dataclass(frozen=True)
class ProofProfile:
    """Proof-system parameters as a first-class, comparable record."""

    name: str
    log_blowup: int
    num_queries: int
    query_proof_of_work_bits: int

    def is_production_grade(self) -> bool:
        """Whether this profile clears the project's provisional soundness floor.

        The 100/3/16 thresholds are provisional engineering gates, not a security
        proof; they exist so a testing profile cannot silently become the shipped
        one. A reviewer may raise them, never lower them without a new review.
        """
        return (
            self.log_blowup >= 3
            and self.num_queries >= 100
            and self.query_proof_of_work_bits >= 16
        )


#: The profile every component prover currently uses (Plonky3 ``new_testing_zk``):
#: two queries at rate 1/4 gives a handful of soundness bits.
RESEARCH_PROOF_PROFILE = ProofProfile(
    name="plonky3-new_testing_zk", log_blowup=2, num_queries=2, query_proof_of_work_bits=1
)

#: Candidate production profile. The values are provisional and must be
#: re-derived from a written FRI/QROM analysis before any launch.
PRODUCTION_PROOF_PROFILE = ProofProfile(
    name="stark-fri-univariate-babybear-v1",
    log_blowup=3,
    num_queries=128,
    query_proof_of_work_bits=16,
)


@dataclass(frozen=True)
class LaunchParameters:
    """The complete frozen consensus parameter block for one network."""

    mode: NetworkMode
    version: int
    chain_id: bytes
    genesis_hash: bytes
    block_interval_seconds: int
    max_transfers_per_block: int
    max_outputs_per_block: int
    max_block_payload_bytes: int
    max_aggregate_fee: int
    min_anchor_age_blocks: int
    max_anchor_age_blocks: int
    proof_profile: ProofProfile
    memo_profile: str
    recipient_discovery: str

    def __post_init__(self) -> None:
        if type(self.mode) is not NetworkMode:
            raise ValueError("mode must be a NetworkMode")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("parameters version must be a positive integer")
        if type(self.chain_id) is not bytes or len(self.chain_id) != 32:
            raise ValueError("chain_id must be exactly 32 bytes")
        if type(self.genesis_hash) is not bytes or len(self.genesis_hash) != 32:
            raise ValueError("genesis_hash must be exactly 32 bytes")
        for name in (
            "block_interval_seconds",
            "max_transfers_per_block",
            "max_outputs_per_block",
            "max_block_payload_bytes",
            "max_aggregate_fee",
            "min_anchor_age_blocks",
            "max_anchor_age_blocks",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if self.block_interval_seconds < 1:
            raise ValueError("block interval must be positive")
        if self.max_transfers_per_block < 1 or self.max_outputs_per_block < 1:
            raise ValueError("per-block item caps must be at least one")
        if self.max_block_payload_bytes < 1:
            raise ValueError("block payload cap must be positive")
        if self.max_aggregate_fee >= 1 << 128:
            raise ValueError("aggregate fee cap must fit a 128-bit limb pair")
        if self.min_anchor_age_blocks > self.max_anchor_age_blocks:
            raise ValueError("minimum anchor age cannot exceed maximum anchor age")
        if type(self.proof_profile) is not ProofProfile:
            raise ValueError("proof_profile must be a ProofProfile")
        if type(self.memo_profile) is not str or not self.memo_profile:
            raise ValueError("memo_profile must be a non-empty string")
        if type(self.recipient_discovery) is not str or not self.recipient_discovery:
            raise ValueError("recipient_discovery must be a non-empty string")

    def canonical_bytes(self) -> bytes:
        """Deterministic encoding; every consensus field is included."""
        p = self.proof_profile
        return frame(
            LAUNCH_PARAMETERS_TAG,
            [
                self.mode.value.encode("ascii"),
                u64(self.version),
                self.chain_id,
                self.genesis_hash,
                u64(self.block_interval_seconds),
                u64(self.max_transfers_per_block),
                u64(self.max_outputs_per_block),
                u64(self.max_block_payload_bytes),
                u64(self.max_aggregate_fee & 0xFFFF_FFFF_FFFF_FFFF),
                u64(self.max_aggregate_fee >> 64),
                u64(self.min_anchor_age_blocks),
                u64(self.max_anchor_age_blocks),
                p.name.encode("ascii"),
                u64(p.log_blowup),
                u64(p.num_queries),
                u64(p.query_proof_of_work_bits),
                self.memo_profile.encode("ascii"),
                self.recipient_discovery.encode("ascii"),
            ],
        )

    def parameters_hash(self) -> bytes:
        """32-byte digest that a reviewer signs. Any field change changes it."""
        return shake_frame(
            LAUNCH_PARAMETERS_HASH_TAG,
            self.canonical_bytes(),
            output_length=PARAMETERS_HASH_BYTES,
        )


def with_mode(parameters: LaunchParameters, mode: NetworkMode) -> LaunchParameters:
    """Return the same block retargeted at ``mode``, refusing silent weakening."""
    if type(mode) is not NetworkMode:
        raise ValueError("mode must be a NetworkMode")
    if mode is NetworkMode.MAINNET:
        if parameters.genesis_hash == PENDING_GENESIS:
            raise LaunchRefused("mainnet requires a finalised genesis")
        if not parameters.proof_profile.is_production_grade():
            raise LaunchRefused(
                "mainnet requires the production proof profile; "
                f"{parameters.proof_profile.name} is a testing profile"
            )
    return replace(parameters, mode=mode)


def finalize_genesis(parameters: LaunchParameters, genesis_hash: bytes) -> LaunchParameters:
    """Bind a generated genesis block hash; the only field set after review."""
    if type(genesis_hash) is not bytes or len(genesis_hash) != 32:
        raise ValueError("genesis hash must be exactly 32 bytes")
    if genesis_hash == PENDING_GENESIS:
        raise ValueError("genesis hash must not be the pending sentinel")
    return replace(parameters, genesis_hash=genesis_hash)


@dataclass(frozen=True)
class Attestation:
    """One reviewer's signature over the manifest payload."""

    reviewer: str
    key_fingerprint: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if type(self.reviewer) is not str or not self.reviewer:
            raise ValueError("reviewer name must be a non-empty string")
        if type(self.key_fingerprint) is not bytes or len(self.key_fingerprint) != 32:
            raise ValueError("reviewer key fingerprint must be 32 bytes")
        if type(self.signature) is not bytes or len(self.signature) != ED25519_SIGNATURE_BYTES:
            raise ValueError("reviewer signature must be 64 bytes")


@dataclass(frozen=True)
class AuditManifest:
    """Signed statement that named reviewers examined these exact parameters."""

    parameters_hash: bytes
    scopes: tuple[str, ...]
    issued_at: int
    attestations: tuple[Attestation, ...]

    def __post_init__(self) -> None:
        if type(self.parameters_hash) is not bytes or len(self.parameters_hash) != PARAMETERS_HASH_BYTES:
            raise ValueError("manifest parameters hash must be 32 bytes")
        if type(self.scopes) is not tuple or not self.scopes:
            raise ValueError("manifest scopes must be a non-empty tuple")
        if any(type(scope) is not str or not scope for scope in self.scopes):
            raise ValueError("manifest scopes must be non-empty strings")
        if type(self.issued_at) is not int or self.issued_at < 0:
            raise ValueError("manifest issue time must be a nonnegative integer")
        if type(self.attestations) is not tuple or not self.attestations:
            raise ValueError("manifest must carry at least one attestation")
        if any(type(item) is not Attestation for item in self.attestations):
            raise ValueError("manifest attestations must be Attestation records")

    def signed_payload(self) -> bytes:
        fields = [
            self.parameters_hash,
            u64(self.issued_at),
            self.scopes[0].encode("ascii"),
        ]
        fields.extend(scope.encode("ascii") for scope in self.scopes[1:])
        return frame(AUDIT_MANIFEST_TAG, fields)


@dataclass(frozen=True)
class LaunchGate:
    """The switch. ``trusted_reviewer_keys`` is the only field a launch edits."""

    parameters: LaunchParameters
    trusted_reviewer_keys: tuple[bytes, ...]
    required_scopes: frozenset[str] = REQUIRED_MAINNET_SCOPES
    minimum_reviewers: int = MINIMUM_MAINNET_REVIEWERS

    def __post_init__(self) -> None:
        if type(self.parameters) is not LaunchParameters:
            raise ValueError("gate parameters must be LaunchParameters")
        if type(self.trusted_reviewer_keys) is not tuple:
            raise ValueError("trusted reviewer keys must be a tuple")
        for key in self.trusted_reviewer_keys:
            if type(key) is not bytes or len(key) != ED25519_PUBLIC_KEY_BYTES:
                raise ValueError("each trusted reviewer key must be 32 Ed25519 bytes")
        if type(self.minimum_reviewers) is not int or self.minimum_reviewers < 1:
            raise ValueError("minimum reviewers must be a positive integer")

    @property
    def is_open(self) -> bool:
        return (
            self.parameters.mode is NetworkMode.MAINNET
            and bool(self.trusted_reviewer_keys)
            and self.parameters.genesis_hash != PENDING_GENESIS
            and self.parameters.proof_profile.is_production_grade()
            and self.parameters.recipient_discovery in REVIEWED_DISCOVERY
        )

    def describe_refusals(self) -> tuple[str, ...]:
        """Everything currently keeping the gate shut, in operator language."""
        reasons: list[str] = []
        if self.parameters.mode is not NetworkMode.MAINNET:
            reasons.append("parameters are not for mainnet mode")
        if not self.trusted_reviewer_keys:
            reasons.append("no independent reviewer public key is trusted")
        elif len(self.trusted_reviewer_keys) < self.minimum_reviewers:
            reasons.append(
                f"fewer than {self.minimum_reviewers} independent reviewer keys are trusted"
            )
        if self.parameters.genesis_hash == PENDING_GENESIS:
            reasons.append("genesis is not finalised")
        if not self.parameters.proof_profile.is_production_grade():
            reasons.append(
                f"proof profile {self.parameters.proof_profile.name!r} is test-grade"
            )
        if self.parameters.recipient_discovery not in REVIEWED_DISCOVERY:
            reasons.append("recipient discovery construction is not reviewed")
        return tuple(reasons)


def open_launch_gate(gate: LaunchGate, manifest: AuditManifest) -> LaunchParameters:
    """Return the mainnet parameters only when every gate condition holds.

    Raises :class:`LaunchRefused` with a specific reason otherwise. This is the
    only function that should be consulted before a node advertises mainnet mode.
    """
    if type(gate) is not LaunchGate or type(manifest) is not AuditManifest:
        raise ValueError("gate and manifest must use the canonical types")
    reasons = list(gate.describe_refusals())
    if reasons:
        raise LaunchRefused("; ".join(reasons))

    if manifest.parameters_hash != gate.parameters.parameters_hash():
        raise LaunchRefused("manifest covers different parameters than the gate")

    missing = gate.required_scopes.difference(manifest.scopes)
    if missing:
        raise LaunchRefused(
            "manifest is missing required review scopes: " + ", ".join(sorted(missing))
        )

    verified: set[bytes] = set()
    payload = manifest.signed_payload()
    for attestation in manifest.attestations:
        key = _match_trusted_key(attestation, gate.trusted_reviewer_keys)
        if key is None:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(
                attestation.signature, payload
            )
        except (InvalidSignature, ValueError):
            continue
        verified.add(attestation.key_fingerprint)

    if len(verified) < gate.minimum_reviewers:
        raise LaunchRefused(
            "fewer than "
            f"{gate.minimum_reviewers} distinct trusted reviewers signed these parameters"
        )
    return gate.parameters


def _match_trusted_key(
    attestation: Attestation, trusted_keys: tuple[bytes, ...]
) -> bytes | None:
    for key in trusted_keys:
        if sha256(key).digest() == attestation.key_fingerprint:
            return key
    return None


# ---------------------------------------------------------------------------
# The shipped configurations.
# ---------------------------------------------------------------------------

_RESEARCH_CHAIN_ID = b"radix-research-chain-id-v1\x00\x00\x00\x00\x00\x00\x00"[:32]

RESEARCH_PARAMETERS = LaunchParameters(
    mode=NetworkMode.RESEARCH,
    version=1,
    chain_id=_RESEARCH_CHAIN_ID,
    genesis_hash=PENDING_GENESIS,
    block_interval_seconds=120,
    max_transfers_per_block=16,
    max_outputs_per_block=16,
    max_block_payload_bytes=1_048_576,
    max_aggregate_fee=16 * (2**64 - 1),
    min_anchor_age_blocks=60,
    max_anchor_age_blocks=10_000,
    proof_profile=RESEARCH_PROOF_PROFILE,
    memo_profile="v1-variable",
    recipient_discovery=UNRESOLVED_DISCOVERY,
)

TESTNET_PARAMETERS = replace(
    RESEARCH_PARAMETERS,
    mode=NetworkMode.TESTNET,
    genesis_hash=shake_frame("radix/testnet-genesis/v1", _RESEARCH_CHAIN_ID, output_length=32),
    recipient_discovery="ml-kem-768-static-reviewed",
)

MAINNET_PARAMETERS = replace(
    RESEARCH_PARAMETERS,
    mode=NetworkMode.MAINNET,
    genesis_hash=PENDING_GENESIS,  # must be finalised from a real genesis block
    max_block_payload_bytes=4_000_000,
    max_transfers_per_block=64,
    max_outputs_per_block=64,
    proof_profile=PRODUCTION_PROOF_PROFILE,
    memo_profile="v1-padded-652",
    recipient_discovery=UNRESOLVED_DISCOVERY,
)

#: ---------------------------------------------------------------------------
#: THE ONE SWITCH.
#:
#: Mainnet is locked because this tuple is empty. To open it, a reviewed commit
#: must (a) add the independent reviewers' Ed25519 public keys here, (b) finalise
#: the genesis in MAINNET_PARAMETERS, and (c) set a reviewed recipient-discovery
#: value. Then supply their signed AuditManifest over MAINNET_PARAMETERS'
#: parameters_hash(). No other code change is required, and no flag can bypass it.
#: ---------------------------------------------------------------------------
MAINNET_SWITCH = LaunchGate(
    parameters=MAINNET_PARAMETERS,
    trusted_reviewer_keys=(),
)

#: The network a node starts in. Research until a human opens the switch above.
DEFAULT_GATE = LaunchGate(
    parameters=RESEARCH_PARAMETERS,
    trusted_reviewer_keys=(),
)
