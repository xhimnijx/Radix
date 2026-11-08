"""Tests for the Fiat-Shamir transcript."""

import pytest

from radix_core.candidate_b.lattice import transcript


def test_determinism():
    first = transcript.Transcript(b"test").absorb(b"a", b"1").challenge(b"c", 32)
    second = transcript.Transcript(b"test").absorb(b"a", b"1").challenge(b"c", 32)
    assert first == second
    assert len(first) == 32


def test_domain_separation():
    left = transcript.Transcript(b"one").absorb(b"a", b"1").challenge(b"c", 32)
    right = transcript.Transcript(b"two").absorb(b"a", b"1").challenge(b"c", 32)
    assert left != right


def test_framing_is_not_concatenation_ambiguous():
    left = transcript.Transcript(b"d").absorb(b"a", b"bc").challenge(b"c", 32)
    right = transcript.Transcript(b"d").absorb(b"ab", b"c").challenge(b"c", 32)
    assert left != right


def test_order_matters():
    forward = (
        transcript.Transcript(b"d").absorb(b"a", b"1").absorb(b"b", b"2").challenge(b"c", 32)
    )
    backward = (
        transcript.Transcript(b"d").absorb(b"b", b"2").absorb(b"a", b"1").challenge(b"c", 32)
    )
    assert forward != backward


def test_squeezing_advances_the_stream():
    session = transcript.Transcript(b"d")
    first = session.challenge(b"c", 32)
    second = session.challenge(b"c", 32)
    assert first != second


def test_clone_reproduces_the_stream_without_consuming_it():
    session = transcript.Transcript(b"d").absorb(b"a", b"1")
    copy = session.clone()
    assert copy.challenge(b"c", 32) == session.challenge(b"c", 32)
    assert session.challenge(b"c", 32) == copy.challenge(b"c", 32)
    assert session.domain == b"d"


def test_polynomial_absorption_is_fixed_width():
    poly = tuple(range(8))
    one = transcript.Transcript(b"d").absorb_poly(b"p", poly).challenge(b"c", 32)
    other = transcript.Transcript(b"d").absorb_poly(b"p", poly).challenge(b"c", 32)
    assert one == other
    with pytest.raises(transcript.TranscriptError):
        transcript.Transcript(b"d").absorb_poly(b"p", (1 << 32,))
    with pytest.raises(transcript.TranscriptError):
        transcript.Transcript(b"d").absorb_poly(b"p", ())


def test_ternary_challenge_is_sparse_and_valued_in_minus_one_to_one():
    challenge = transcript.Transcript(b"d").challenge_ternary(b"c", 128, 10)
    assert len(challenge) == 128
    assert sum(1 for value in challenge if value) == 10
    assert set(challenge) <= {-1, 0, 1}


def test_ternary_challenge_varies_with_the_transcript():
    left = transcript.Transcript(b"d").absorb(b"a", b"1").challenge_ternary(b"c", 128, 10)
    right = transcript.Transcript(b"d").absorb(b"a", b"2").challenge_ternary(b"c", 128, 10)
    assert left != right


def test_malformed_inputs_are_rejected():
    with pytest.raises(transcript.TranscriptError):
        transcript.Transcript(b"")
    with pytest.raises(transcript.TranscriptError):
        transcript.Transcript(b"d").absorb(b"a", "text")
    with pytest.raises(transcript.TranscriptError):
        transcript.Transcript(b"d").challenge(b"c", 0)
    with pytest.raises(transcript.TranscriptError):
        transcript.Transcript(b"d").challenge(b"c", 1 << 17)
    with pytest.raises(transcript.TranscriptError):
        transcript.Transcript(b"d").challenge_ternary(b"c", 8, 9)
    with pytest.raises(transcript.TranscriptError):
        transcript.Transcript(b"d").absorb(b"x" * 256, b"p")
