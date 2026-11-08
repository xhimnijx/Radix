"""Tests for tensor / one-hot indexing (SMILE Fig. 6 support layer)."""

import pytest

from radix_core.candidate_b.lattice import ring, tensor


def test_one_hot_shape_and_values():
    vector = tensor.one_hot(5, 3)
    assert vector == (0, 0, 0, 1, 0)
    assert tensor.assert_one_hot(vector) == 3
    for bad in (5, -1):
        with pytest.raises(tensor.TensorError):
            tensor.one_hot(5, bad)


def test_assert_one_hot_rejects_non_unit_vectors():
    for bad in ((0, 0), (1, 1), (0, 2), (0, -1), ()):
        with pytest.raises(tensor.TensorError):
            tensor.assert_one_hot(bad)


def test_kronecker_product_places_the_index_in_base_l():
    left = tensor.one_hot(32, 5)
    right = tensor.one_hot(32, 7)
    product = tensor.kron(left, right)
    assert len(product) == 32 * 32
    assert tensor.assert_one_hot(product) == 5 * 32 + 7
    assert product == tensor.one_hot(32 * 32, 5 * 32 + 7)


def test_tensor_of_one_hots_is_one_hot_at_the_flat_index():
    indices = (31, 0, 17)
    vectors = tuple(tensor.one_hot(32, index) for index in indices)
    product = tensor.tensor(vectors)
    expected = tensor.flat_index(indices, 32)
    assert len(product) == 32**3
    assert tensor.assert_one_hot(product) == expected
    assert expected == 31 * 32 * 32 + 17


def test_set_size_and_flat_index_agree():
    for m in (1, 2, 3):
        indices = tuple((7 * m + index) % 32 for index in range(m))
        assert tensor.flat_index(indices, 32) < tensor.set_size(m, 32)
    assert tensor.set_size(1) == 32
    assert tensor.set_size(3) == 32**3


def test_flat_index_rejects_out_of_range_indices():
    with pytest.raises(tensor.TensorError):
        tensor.flat_index((0, 32), 32)
    with pytest.raises(tensor.TensorError):
        tensor.flat_index((), 32)


def test_select_columns_returns_the_selected_column_only():
    columns = tuple(ring.constant(index + 1) for index in range(4))
    weights = tensor.one_hot(4, 2)
    assert tensor.select_columns(columns, weights) == ring.constant(3)


def test_select_columns_refuses_non_one_hot_weights_and_shape_mismatch():
    columns = tuple(ring.constant(index) for index in range(4))
    with pytest.raises(tensor.TensorError):
        tensor.select_columns(columns, (2, 0, 0, 0))
    with pytest.raises(tensor.TensorError):
        tensor.select_columns(columns, (1, 0, 0))


def test_sixty_four_bit_index_space_is_addressable():
    # m = 5 at l = 32 gives 2^25 = 33,554,432 elements, matching SMILE's max ring.
    assert tensor.set_size(5, 32) == 2**25
    assert tensor.flat_index((31,) * 5, 32) == 2**25 - 1
