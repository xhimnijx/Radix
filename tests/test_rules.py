from radix_core.encoding import U64_MAX
from radix_core.rules import BlockHeaderRef, anchor_ok, balance_ok


def test_balance_uses_bounded_plain_integers():
    assert balance_ok([9, 7], [13, 3], 0)
    assert balance_ok([U64_MAX], [U64_MAX - 1], 1)
    assert balance_ok([U64_MAX, U64_MAX], [U64_MAX, U64_MAX], 0)
    assert balance_ok([U64_MAX], [U64_MAX], 0)
    assert not balance_ok([U64_MAX], [U64_MAX], 1)
    assert not balance_ok([1], [0], 1)
    assert not balance_ok([True], [1], 0)
    assert not balance_ok([1], [1], True)
    assert not balance_ok([1] * 17, [1], 0)
    assert not balance_ok([1], [1] * 17, 0)
    assert not balance_ok([], [1], 0)
    assert not balance_ok([1], [1], -1)
    assert not balance_ok([1], [1], 1 << 64)


def make_chain(prefix: int, anchor_root: bytes) -> dict[bytes, BlockHeaderRef]:
    headers: dict[bytes, BlockHeaderRef] = {}
    parent_id = None
    for height in range(120):
        block_id = prefix.to_bytes(4, "little") + height.to_bytes(28, "little")
        root = anchor_root if height == 60 else bytes([height % 251]) * 64
        header = BlockHeaderRef(block_id, parent_id, height, root)
        headers[block_id] = header
        parent_id = block_id
    return headers


def test_anchor_boundary_is_branch_relative_and_reorg_sensitive():
    root_a, root_b = b"a" * 64, b"b" * 64
    chain_a = make_chain(1, root_a)
    chain_b = make_chain(2, root_b)
    parent_a = next(header.block_id for header in chain_a.values() if header.height == 119)
    parent_b = next(header.block_id for header in chain_b.values() if header.height == 119)

    assert anchor_ok(120, parent_a, 60, root_a, chain_a)
    assert anchor_ok(120, parent_b, 60, root_b, chain_b)
    assert not anchor_ok(120, parent_b, 60, root_a, chain_b)
    assert not anchor_ok(119, parent_a, 60, root_a, chain_a)  # age 59
    assert not anchor_ok(120, parent_a, 121, root_a, chain_a)  # future anchor
    assert not anchor_ok(120, b"z" * 32, 60, root_a, chain_a)  # missing parent


def test_anchor_rejects_missing_ancestor_and_wrong_height_link():
    root = b"r" * 64
    chain = make_chain(3, root)
    parent = next(header for header in chain.values() if header.height == 119)
    del chain[parent.parent_id]
    assert not anchor_ok(120, parent.block_id, 60, root, chain)

    broken = make_chain(4, root)
    parent = next(header for header in broken.values() if header.height == 119)
    broken[parent.block_id] = BlockHeaderRef(parent.block_id, parent.parent_id, 118, parent.output_root)
    assert not anchor_ok(120, parent.block_id, 60, root, broken)


def test_anchor_fails_closed_on_mutated_header_fields():
    for field, invalid_value in (
        ("parent_id", []),
        ("height", "not a U64"),
        ("output_root", []),
    ):
        root = b"m" * 64
        headers = make_chain(7, root)
        parent = next(header for header in headers.values() if header.height == 119)
        ancestor = next(header for header in headers.values() if header.height == 100)
        object.__setattr__(ancestor, field, invalid_value)
        assert not anchor_ok(120, parent.block_id, 60, root, headers)


def test_anchor_rejects_wrong_type_header_index_values():
    root = b"t" * 64
    parent_headers = make_chain(5, root)
    parent = next(header for header in parent_headers.values() if header.height == 119)
    parent_headers[parent.block_id] = object()
    assert not anchor_ok(120, parent.block_id, 60, root, parent_headers)

    ancestor_headers = make_chain(6, root)
    parent = next(header for header in ancestor_headers.values() if header.height == 119)
    ancestor = next(header for header in ancestor_headers.values() if header.height == 100)
    ancestor_headers[ancestor.block_id] = object()
    assert not anchor_ok(120, parent.block_id, 60, root, ancestor_headers)
