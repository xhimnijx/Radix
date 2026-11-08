//! Minimal composition of the isolated spend-key and one-time-owner hash proofs.
//!
//! This is a proof bundle with two independently Fiat-Shamir-bound STARKs, not one composed
//! transaction proof. The verifier enforces that both child statements use the same `pk_s`.

use std::{error::Error, fmt};

use crate::{note_owner_opening, spend_pk_opening};

const PUBLIC_BYTES: usize = 64;
const MAGIC: &[u8; 8] = b"RDXBND01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 8 + 2 + PUBLIC_BYTES * 2 + 4 + 4;
const MAX_CHILD_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + 2 * MAX_CHILD_BYTES;

#[derive(Debug, PartialEq, Eq)]
pub enum OwnerBundleError {
    Malformed(&'static str),
    Component(String),
    PublicKeyMismatch,
    OwnerMismatch,
}

impl fmt::Display for OwnerBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => {
                write!(formatter, "malformed owner-binding bundle: {message}")
            }
            Self::Component(message) => write!(formatter, "component proof failed: {message}"),
            Self::PublicKeyMismatch => {
                write!(formatter, "spend-key proofs bind different public keys")
            }
            Self::OwnerMismatch => write!(formatter, "bundle owner does not match owner subproof"),
        }
    }
}

impl Error for OwnerBundleError {}

fn encode(
    spend_public_key: &[u8; PUBLIC_BYTES],
    owner: &[u8; PUBLIC_BYTES],
    spend_proof: &[u8],
    owner_proof: &[u8],
) -> Result<Vec<u8>, OwnerBundleError> {
    if spend_proof.is_empty()
        || owner_proof.is_empty()
        || spend_proof.len() > MAX_CHILD_BYTES
        || owner_proof.len() > MAX_CHILD_BYTES
    {
        return Err(OwnerBundleError::Malformed(
            "child proof size out of bounds",
        ));
    }
    let spend_len = u32::try_from(spend_proof.len())
        .map_err(|_| OwnerBundleError::Malformed("spend proof too large"))?;
    let owner_len = u32::try_from(owner_proof.len())
        .map_err(|_| OwnerBundleError::Malformed("owner proof too large"))?;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + spend_proof.len() + owner_proof.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(spend_public_key);
    bytes.extend_from_slice(owner);
    bytes.extend_from_slice(&spend_len.to_le_bytes());
    bytes.extend_from_slice(&owner_len.to_le_bytes());
    bytes.extend_from_slice(spend_proof);
    bytes.extend_from_slice(owner_proof);
    Ok(bytes)
}

fn decode(
    bytes: &[u8],
) -> Result<([u8; PUBLIC_BYTES], [u8; PUBLIC_BYTES], &[u8], &[u8]), OwnerBundleError> {
    if bytes.len() < HEADER_BYTES {
        return Err(OwnerBundleError::Malformed("truncated envelope"));
    }
    if bytes.len() > HEADER_BYTES + 2 * MAX_CHILD_BYTES {
        return Err(OwnerBundleError::Malformed("envelope exceeds size limit"));
    }
    if &bytes[..8] != MAGIC {
        return Err(OwnerBundleError::Malformed("wrong magic"));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if version != VERSION {
        return Err(OwnerBundleError::Malformed("unsupported version"));
    }
    let spend_public_key: [u8; PUBLIC_BYTES] = bytes[10..74].try_into().unwrap();
    let owner: [u8; PUBLIC_BYTES] = bytes[74..138].try_into().unwrap();
    let spend_len = u32::from_le_bytes(bytes[138..142].try_into().unwrap()) as usize;
    let owner_len = u32::from_le_bytes(bytes[142..146].try_into().unwrap()) as usize;
    if spend_len == 0
        || owner_len == 0
        || spend_len > MAX_CHILD_BYTES
        || owner_len > MAX_CHILD_BYTES
    {
        return Err(OwnerBundleError::Malformed("child length out of bounds"));
    }
    let expected = HEADER_BYTES
        .checked_add(spend_len)
        .and_then(|length| length.checked_add(owner_len))
        .ok_or(OwnerBundleError::Malformed("length overflow"))?;
    if bytes.len() != expected {
        return Err(OwnerBundleError::Malformed(
            "length mismatch or trailing bytes",
        ));
    }
    let spend_end = HEADER_BYTES + spend_len;
    Ok((
        spend_public_key,
        owner,
        &bytes[HEADER_BYTES..spend_end],
        &bytes[spend_end..],
    ))
}

/// Prove both fixed hash subrelations and package them with a common spend public key.
pub fn prove_owner_binding_bundle(
    spend_secret: &[u8; 64],
    shared_secret: &[u8; 32],
) -> Result<Vec<u8>, OwnerBundleError> {
    let (spend_public_key, spend_proof) =
        spend_pk_opening::prove_spend_pk_with_public_key(spend_secret)
            .map_err(|error| OwnerBundleError::Component(error.to_string()))?;
    let (owner, owner_proof) =
        note_owner_opening::prove_note_owner_with_output(&spend_public_key, shared_secret)
            .map_err(|error| OwnerBundleError::Component(error.to_string()))?;
    encode(&spend_public_key, &owner, &spend_proof, &owner_proof)
}

/// Verify both subproofs and enforce a common public spend key and owner.
pub fn verify_owner_binding_bundle(
    bytes: &[u8],
) -> Result<([u8; PUBLIC_BYTES], [u8; PUBLIC_BYTES]), OwnerBundleError> {
    let (spend_public_key, owner, spend_proof, owner_proof) = decode(bytes)?;
    let verified_spend_key = spend_pk_opening::verify_spend_pk(spend_proof)
        .map_err(|error| OwnerBundleError::Component(error.to_string()))?;
    let (owner_spend_key, verified_owner) = note_owner_opening::verify_note_owner(owner_proof)
        .map_err(|error| OwnerBundleError::Component(error.to_string()))?;
    if verified_spend_key != spend_public_key || owner_spend_key != spend_public_key {
        return Err(OwnerBundleError::PublicKeyMismatch);
    }
    if verified_owner != owner {
        return Err(OwnerBundleError::OwnerMismatch);
    }
    Ok((spend_public_key, owner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_hash_bundle_verifies_and_rejects_tampering() {
        let spend_secret = core::array::from_fn(|index| index as u8);
        let shared_secret = core::array::from_fn(|index| index as u8);
        let bundle = prove_owner_binding_bundle(&spend_secret, &shared_secret).unwrap();
        let (spend_public_key, owner) = verify_owner_binding_bundle(&bundle).unwrap();
        assert_eq!(
            spend_public_key,
            hex_array(
                "6790c030ce689c30e5e0f77ecae4cafef32d1babf458e7b2e54d6c1485c867576d2b5455f35507e1348e545f4c61f88b65979579d188008690b6e3659ef51559"
            )
        );
        assert_eq!(
            owner,
            hex_array(
                "cc4810af2987d299ac9389d6473d7095c7ff72498ddd635e5379a8a2cb9cd8a5f05ff4946addde3c34e035a4cdf766d39912b239cb382ee2038f37c2348dc06e"
            )
        );

        let mut changed_statement = bundle.clone();
        changed_statement[10] ^= 1;
        assert!(verify_owner_binding_bundle(&changed_statement).is_err());

        let mut changed_owner = bundle.clone();
        changed_owner[74] ^= 1;
        assert!(verify_owner_binding_bundle(&changed_owner).is_err());

        let mut changed_child = bundle.clone();
        changed_child[HEADER_BYTES + 10] ^= 1;
        assert!(verify_owner_binding_bundle(&changed_child).is_err());

        let mut trailing = bundle;
        trailing.push(0);
        assert!(verify_owner_binding_bundle(&trailing).is_err());
    }

    fn hex_array(text: &str) -> [u8; PUBLIC_BYTES] {
        core::array::from_fn(|index| {
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()
        })
    }
}
