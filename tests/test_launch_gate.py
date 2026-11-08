"""Tests for the mainnet launch gate.

The contract under test: mainnet is refused by default, every consensus field is
covered by the reviewer's signature, and opening the gate is one reviewed edit
plus a signed manifest — not a code path or an environment flag.
"""

from dataclasses import replace
from hashlib import sha256

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from radix_core.launch import (
    MAINNET_PARAMETERS,
    MAINNET_SWITCH,
    REQUIRED_MAINNET_SCOPES,
    RESEARCH_PARAMETERS,
    TESTNET_PARAMETERS,
    UNRESOLVED_DISCOVERY,
    Attestation,
    AuditManifest,
    LaunchGate,
    LaunchRefused,
    NetworkMode,
    PENDING_GENESIS,
    finalize_genesis,
    open_launch_gate,
    with_mode,
)

ISSUED_AT = 1_760_000_000


class Signer:
    def __init__(self, name: str) -> None:
        self.name = name
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes_raw()
        self.fingerprint = sha256(self.public).digest()

    def sign(self, payload: bytes) -> Attestation:
        return Attestation(self.name, self.fingerprint, self.private.sign(payload))


def _resolved_mainnet():
    """A mainnet block with the genesis and discovery blocker resolved."""
    parameters = finalize_genesis(MAINNET_PARAMETERS, b"\x11" * 32)
    return replace(parameters, recipient_discovery="pq-stealth-address-v1")


def _manifest(parameters, signers, scopes=frozenset(REQUIRED_MAINNET_SCOPES)):
    placeholder = AuditManifest(
        parameters_hash=parameters.parameters_hash(),
        scopes=tuple(sorted(scopes)),
        issued_at=ISSUED_AT,
        attestations=(Attestation("placeholder", b"\x00" * 32, b"\x00" * 64),),
    )
    payload = placeholder.signed_payload()
    return replace(
        placeholder, attestations=tuple(signer.sign(payload) for signer in signers)
    )


def test_the_shipped_mainnet_switch_is_closed():
    assert MAINNET_SWITCH.is_open is False
    assert MAINNET_SWITCH.trusted_reviewer_keys == ()
    assert MAINNET_SWITCH.describe_refusals()


def test_a_valid_manifest_cannot_open_the_shipped_switch():
    alice, bob = Signer("alice"), Signer("bob")
    manifest = _manifest(MAINNET_PARAMETERS, (alice, bob))
    with pytest.raises(LaunchRefused):
        open_launch_gate(MAINNET_SWITCH, manifest)


def test_gate_opens_with_two_trusted_reviewers_over_the_same_parameters():
    alice, bob = Signer("alice"), Signer("bob")
    parameters = _resolved_mainnet()
    gate = LaunchGate(parameters, (alice.public, bob.public))

    assert open_launch_gate(gate, _manifest(parameters, (alice, bob))) == parameters


def test_a_single_reviewer_is_not_enough():
    alice = Signer("alice")
    parameters = _resolved_mainnet()
    gate = LaunchGate(parameters, (alice.public,))

    with pytest.raises(LaunchRefused, match="fewer than|independent reviewer"):
        open_launch_gate(gate, _manifest(parameters, (alice,)))


def test_changing_any_consensus_field_invalidates_the_manifest():
    alice, bob = Signer("alice"), Signer("bob")
    parameters = _resolved_mainnet()
    manifest = _manifest(parameters, (alice, bob))
    gate = LaunchGate(replace(parameters, max_block_payload_bytes=8_000_000), (alice.public, bob.public))

    with pytest.raises(LaunchRefused, match="different parameters"):
        open_launch_gate(gate, manifest)


def test_an_untrusted_signer_is_not_counted():
    alice, bob, mallory = Signer("alice"), Signer("bob"), Signer("mallory")
    parameters = _resolved_mainnet()
    gate = LaunchGate(parameters, (alice.public, bob.public))

    with pytest.raises(LaunchRefused, match="distinct trusted reviewers"):
        open_launch_gate(gate, _manifest(parameters, (alice, mallory)))


def test_a_tampered_signature_is_rejected():
    alice, bob = Signer("alice"), Signer("bob")
    parameters = _resolved_mainnet()
    manifest = _manifest(parameters, (alice, bob))
    tampered = replace(
        manifest,
        attestations=(
            replace(manifest.attestations[0], signature=b"\x00" * 64),
            manifest.attestations[1],
        ),
    )
    gate = LaunchGate(parameters, (alice.public, bob.public))

    with pytest.raises(LaunchRefused, match="distinct trusted reviewers"):
        open_launch_gate(gate, tampered)


def test_missing_review_scope_blocks_the_launch():
    alice, bob = Signer("alice"), Signer("bob")
    parameters = _resolved_mainnet()
    gate = LaunchGate(parameters, (alice.public, bob.public))
    partial = _manifest(parameters, (alice, bob), frozenset({"soundness", "zero-knowledge"}))

    with pytest.raises(LaunchRefused, match="missing required review scopes"):
        open_launch_gate(gate, partial)


def test_test_grade_proof_parameters_cannot_be_promoted_to_mainnet():
    with_genesis = finalize_genesis(RESEARCH_PARAMETERS, b"\x44" * 32)
    with pytest.raises(LaunchRefused, match="production proof profile"):
        with_mode(with_genesis, NetworkMode.MAINNET)


def test_pending_genesis_blocks_the_launch():
    parameters = replace(
        _resolved_mainnet(), genesis_hash=PENDING_GENESIS, mode=NetworkMode.MAINNET
    )
    alice, bob = Signer("alice"), Signer("bob")
    gate = LaunchGate(parameters, (alice.public, bob.public))

    with pytest.raises(LaunchRefused, match="genesis"):
        open_launch_gate(gate, _manifest(parameters, (alice, bob)))


def test_unreviewed_recipient_discovery_blocks_the_launch():
    parameters = replace(_resolved_mainnet(), recipient_discovery=UNRESOLVED_DISCOVERY)
    alice, bob = Signer("alice"), Signer("bob")
    gate = LaunchGate(parameters, (alice.public, bob.public))

    with pytest.raises(LaunchRefused, match="recipient discovery"):
        open_launch_gate(gate, _manifest(parameters, (alice, bob)))


def test_research_and_testnet_do_not_require_the_gate():
    assert RESEARCH_PARAMETERS.mode is NetworkMode.RESEARCH
    assert TESTNET_PARAMETERS.genesis_hash != PENDING_GENESIS
    assert TESTNET_PARAMETERS.proof_profile.is_production_grade() is False


def test_parameters_hash_covers_every_field():
    base = _resolved_mainnet()
    seen = {base.parameters_hash()}
    mutations = (
        {"block_interval_seconds": 60},
        {"max_transfers_per_block": 1},
        {"max_outputs_per_block": 1},
        {"max_block_payload_bytes": 1},
        {"max_aggregate_fee": 1},
        {"min_anchor_age_blocks": 61},
        {"max_anchor_age_blocks": 10_001},
        {"memo_profile": "other"},
        {"recipient_discovery": "pq-stealth-address-reviewed"},
        {"version": 2},
        {"chain_id": b"\x22" * 32},
        {"genesis_hash": b"\x33" * 32},
    )
    for mutation in mutations:
        seen.add(replace(base, **mutation).parameters_hash())
    assert len(seen) == len(mutations) + 1
