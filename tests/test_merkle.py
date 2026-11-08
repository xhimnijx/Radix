import pytest

from radix_core.crypto import TREE_NODE, shake_frame
from radix_core.encoding import u8
from radix_core.merkle import (
    CAPACITY,
    DEPTH,
    EMPTY_HASHES,
    EMPTY_ROOT,
    OutputTree,
    check_append_capacity,
    root_from_path,
    verify_membership,
)


def naive_root(leaves: list[bytes]) -> bytes:
    nodes = dict(enumerate(leaves))
    for level in range(DEPTH):
        parents = {index >> 1 for index in nodes}
        next_nodes = {}
        for parent in parents:
            left = nodes.get(parent << 1, EMPTY_HASHES[level])
            right = nodes.get((parent << 1) + 1, EMPTY_HASHES[level])
            value = shake_frame(TREE_NODE, u8(level), left, right)
            if value != EMPTY_HASHES[level + 1]:
                next_nodes[parent] = value
        nodes = next_nodes
    return nodes.get(0, EMPTY_ROOT)


def test_empty_root_and_depth_defaults_are_defined():
    assert len(EMPTY_HASHES) == 65
    assert EMPTY_ROOT == EMPTY_HASHES[64]
    assert OutputTree().root == EMPTY_ROOT
    assert len(EMPTY_ROOT) == 64


def test_reserved_empty_leaf_cannot_become_a_populated_output():
    tree = OutputTree()
    before = (tree.root, tree.leaf_count)
    with pytest.raises(ValueError, match="reserved empty-leaf"):
        tree.append(EMPTY_HASHES[0])
    assert (tree.root, tree.leaf_count) == before

    # Integrity checking must catch a corrupted snapshot with the same alias.
    tree._nodes[0][0] = EMPTY_HASHES[0]
    tree._leaf_count = 1
    with pytest.raises(ValueError, match="reserved empty-leaf"):
        tree.validate_integrity()


def test_append_roots_match_independent_recomputation_and_paths():
    leaves = [bytes([n]) * 64 for n in (1, 2, 3, 4, 5)]
    tree = OutputTree()
    for index, leaf in enumerate(leaves):
        assert tree.append(leaf) == index
        assert tree.leaf_count == index + 1
        assert tree.root == naive_root(leaves[: index + 1])
        tree.validate_integrity()
        path = tree.authentication_path(index)
        assert len(path) == DEPTH
        assert root_from_path(leaf, index, path) == tree.root
        assert verify_membership(leaf, index, path, tree.root)
    assert tree.leaf_at(2) == leaves[2]
    with pytest.raises(ValueError):
        tree.leaf_at(5)


def test_append_preserves_prior_root_snapshot_and_clone_is_independent():
    tree = OutputTree()
    leaf0 = b"a" * 64
    tree.append(leaf0)
    old_root = tree.root
    old_path = tree.authentication_path(0)
    clone = tree.clone()
    tree.append(b"b" * 64)
    assert clone.root == old_root
    assert root_from_path(leaf0, 0, old_path) == old_root
    assert tree.root != old_root


def test_capacity_math_models_the_65_bit_count_boundary():
    assert check_append_capacity(CAPACITY - 1, 1) == CAPACITY
    assert check_append_capacity(CAPACITY, 0) == CAPACITY
    for count, amount in ((CAPACITY, 1), (CAPACITY - 1, 2), (-1, 0), (0, -1), (True, 0)):
        with pytest.raises(ValueError):
            check_append_capacity(count, amount)


def test_high_bit_index_orientation_and_path_length_are_exact():
    leaf = b"l" * 64
    path = tuple(bytes([index + 1]) * 64 for index in range(DEPTH))
    index = 1 << 63
    root = root_from_path(leaf, index, path)
    assert verify_membership(leaf, index, path, root)
    assert not verify_membership(leaf, index ^ (1 << 63), path, root)
    assert not verify_membership(leaf, index, path[:-1], root)


def test_root_from_path_accepts_exact_iterators_and_bounds_overlong_iterators():
    leaf = b"l" * 64
    path = tuple(bytes([index + 1]) * 64 for index in range(DEPTH))
    expected = root_from_path(leaf, 0, path)
    assert root_from_path(leaf, 0, (sibling for sibling in path)) == expected

    consumed = 0

    def endless_siblings():
        nonlocal consumed
        while True:
            consumed += 1
            yield b"s" * 64

    with pytest.raises(ValueError, match="exactly 64 siblings"):
        root_from_path(leaf, 0, endless_siblings())
    assert consumed == DEPTH + 1


def test_append_many_is_atomic_on_invalid_batch():
    tree = OutputTree()
    tree.append(b"x" * 64)
    before = (tree.root, tree.leaf_count)
    with pytest.raises(ValueError):
        tree.append_many((b"y" * 64, b"short"))
    assert (tree.root, tree.leaf_count) == before


def test_integrity_recomputation_accepts_valid_trees_and_rejects_corrupt_node_maps():
    tree = OutputTree()
    tree.validate_integrity()
    tree.append_many((b"a" * 64, b"b" * 64, b"c" * 64))
    tree.validate_integrity()

    tree._nodes[64][0] = b"z" * 64
    with pytest.raises(ValueError, match="inconsistent"):
        tree.validate_integrity()
    corrupted_snapshot = [level.copy() for level in tree._nodes]
    with pytest.raises(ValueError, match="inconsistent"):
        tree.append(b"d" * 64)
    assert tree._nodes == corrupted_snapshot
