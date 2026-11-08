"""Small offline demonstration of the implemented Candidate-A wallet slice.

This does not submit a transaction, check consensus, or demonstrate anonymity.
It creates one recipient output, recovers it locally, and proves membership in
an in-memory tree containing only that output.
"""
from __future__ import annotations

import base64

from radix_core.cryptography_backend import (
    CryptographyAes256GcmProvider,
    CryptographyMlKem768Provider,
)
from radix_core.merkle import OutputTree, verify_membership
from radix_core.providers import AeadNonceRegistry
from radix_core.wallet import (
    create_note_output_for_address_v1,
    generate_wallet_keys_v1,
    recover_note_v1,
    serialize_wallet_address_v1,
)


def main() -> None:
    chain_id = b"RADIX-OFFLINE-DEMO-V1".ljust(32, b"\0")
    kem = CryptographyMlKem768Provider()
    aead = CryptographyAes256GcmProvider()
    recipient = generate_wallet_keys_v1(kem)
    address = serialize_wallet_address_v1(recipient, chain_id)

    created = create_note_output_for_address_v1(
        kem,
        aead,
        address,
        value=42,
        memo=b"offline wallet demonstration",
        expected_chain_id=chain_id,
        nonce_registry=AeadNonceRegistry(max_entries=1),
    )
    recovered = recover_note_v1(
        kem,
        aead,
        recipient.decapsulation_key,
        recipient.spend_secret,
        created.output,
    )
    if (
        recovered is None
        or recovered.value != 42
        or recovered.memo != b"offline wallet demonstration"
    ):
        raise RuntimeError("recipient failed to recover the locally created note")

    tree = OutputTree()
    output_index = tree.append(created.output.leaf)
    path = tree.authentication_path(output_index)
    if not verify_membership(created.output.leaf, output_index, path, tree.root):
        raise RuntimeError("local output-tree membership check failed")

    print("Radix Candidate-A offline wallet demo (no network or consensus)")
    print(f"Chain ID: {chain_id.hex()}")
    encoded_address = base64.b64encode(address).decode("ascii")
    print("Recipient address (base64 of canonical binary address):")
    print(encoded_address)
    print(f"Created output leaf: {created.output.leaf.hex()}")
    print(f"Local one-output tree root: {tree.root.hex()}")
    print(f"Membership at output index {output_index}: valid")
    print(f"Recipient recovered value: {recovered.value}")
    print(f"Recipient recovered memo: {recovered.memo.decode('utf-8')}")
    print(
        "No transaction proof, consensus acceptance, network, or anonymity claim "
        "is included."
    )


if __name__ == "__main__":
    main()
