use super::bounded_postcard::{self, Budget, Limits, MAX_PROOF_SEQUENCE_ELEMENTS};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

fn assert_budget_error(err: postcard::Error) {
    assert!(
        matches!(err, postcard::Error::SerdeDeCustom),
        "unexpected error: {err:?}"
    );
}

fn budget(sequence_elements: usize, decoded_bytes: usize) -> Budget {
    Budget::new(Limits {
        sequence_elements,
        decoded_bytes,
    })
}

#[test]
fn proof_decode_entrypoint_decodes_small_value() {
    let wire = postcard::to_allocvec(&vec![2_u8, 7, 1]).unwrap();
    assert_eq!(
        bounded_postcard::from_proof_bytes::<Vec<u8>>(&wire).unwrap(),
        vec![2, 7, 1]
    );
}

#[test]
fn proof_decode_entrypoint_rejects_above_source_derived_element_ceiling() {
    let values = vec![0_u8; MAX_PROOF_SEQUENCE_ELEMENTS + 1];
    let wire = postcard::to_allocvec(&values).unwrap();
    let err = bounded_postcard::from_proof_bytes::<Vec<u8>>(&wire).unwrap_err();
    assert_budget_error(err);
}

#[test]
fn known_sequence_length_is_charged_before_elements_are_read() {
    let wire = postcard::to_allocvec(&vec![1_u8, 2, 3]).unwrap();
    let mut too_small = budget(2, wire.len());
    let err = bounded_postcard::from_bytes::<Vec<u8>>(&wire, &mut too_small).unwrap_err();
    assert_budget_error(err);

    let mut exact = budget(3, wire.len());
    assert_eq!(
        bounded_postcard::from_bytes::<Vec<u8>>(&wire, &mut exact).unwrap(),
        vec![1, 2, 3]
    );
    assert_eq!(exact.sequence_elements_used(), 3);
}

#[test]
fn oversized_known_sequence_is_rejected_before_elements_are_read() {
    let values: Vec<u8> = (0..128).collect();
    let wire = postcard::to_allocvec(&values).unwrap();
    let mut limits = budget(4, wire.len());
    let err = bounded_postcard::from_bytes::<Vec<u8>>(&wire, &mut limits).unwrap_err();
    assert_budget_error(err);
    assert_eq!(limits.sequence_elements_used(), 0);
}

#[test]
fn decoded_byte_budget_applies_to_strings_and_aggregates_nested_values() {
    let string_wire = postcard::to_allocvec("bounded").unwrap();
    let mut short = budget(string_wire.len(), 6);
    let err = bounded_postcard::from_bytes::<String>(&string_wire, &mut short).unwrap_err();
    assert_budget_error(err);

    let nested_wire = postcard::to_allocvec(&vec![String::from("a"), String::from("bc")]).unwrap();
    let mut aggregate_short = budget(2, 2);
    let err = bounded_postcard::from_bytes::<Vec<String>>(&nested_wire, &mut aggregate_short)
        .unwrap_err();
    assert_budget_error(err);

    let mut exact = budget(2, 3);
    assert_eq!(
        bounded_postcard::from_bytes::<Vec<String>>(&nested_wire, &mut exact).unwrap(),
        vec![String::from("a"), String::from("bc")]
    );
    assert_eq!(exact.sequence_elements_used(), 2);
    assert_eq!(exact.decoded_bytes_used(), 3);
}

#[test]
fn nested_known_sequences_share_one_aggregate_element_budget() {
    let nested = vec![vec![1_u8, 2], vec![3, 4]];
    let wire = postcard::to_allocvec(&nested).unwrap();

    // Two outer elements and four inner elements are charged as one traversal.
    let mut short = budget(5, wire.len());
    let err = bounded_postcard::from_bytes::<Vec<Vec<u8>>>(&wire, &mut short).unwrap_err();
    assert_budget_error(err);
    assert_eq!(short.sequence_elements_used(), 4);

    let mut exact = budget(6, wire.len());
    assert_eq!(
        bounded_postcard::from_bytes::<Vec<Vec<u8>>>(&wire, &mut exact).unwrap(),
        nested
    );
    assert_eq!(exact.sequence_elements_used(), 6);
}

struct ReportsSuppressedSizeHint;

impl<'de> Deserialize<'de> for ReportsSuppressedSizeHint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HintVisitor;

        impl<'de> Visitor<'de> for HintVisitor {
            type Value = ReportsSuppressedSizeHint;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence whose size hint is hidden")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence.size_hint().is_some() {
                    return Err(de::Error::custom("size hint was exposed"));
                }
                while sequence.next_element::<u8>()?.is_some() {}
                Ok(ReportsSuppressedSizeHint)
            }
        }

        deserializer.deserialize_seq(HintVisitor)
    }
}

#[test]
fn attacker_controlled_collection_size_hint_is_hidden_from_visitor() {
    let wire = postcard::to_allocvec(&vec![4_u8, 5, 6]).unwrap();
    let mut limits = budget(3, wire.len());
    bounded_postcard::from_bytes::<ReportsSuppressedSizeHint>(&wire, &mut limits).unwrap();
    assert_eq!(limits.sequence_elements_used(), 3);
}

#[test]
fn adapter_suffix_behavior_is_explicit_and_requires_caller_canonical_check() {
    let mut wire = postcard::to_allocvec(&vec![9_u8, 8]).unwrap();
    wire.push(0xff);
    let mut limits = budget(2, wire.len());
    assert_eq!(
        bounded_postcard::from_bytes::<Vec<u8>>(&wire, &mut limits).unwrap(),
        vec![9, 8]
    );
}
