//! Strict Rust codec for the experimental Candidate-A 1-input/1-output statement.
//!
//! This is host-side parsing/serialization only. It is not a transaction proof and
//! does not establish that a private witness matches the public fields.

use std::{error::Error, fmt};

use tiny_keccak::{Hasher, Shake};

const FRAME_MAGIC: &[u8; 5] = b"RADIX";
const FRAME_VERSION: u8 = 1;
const STATEMENT_TAG: &[u8] = b"radix/tx-statement/v1";
const OUTPUT_TAG: &[u8] = b"radix/output/v1";
const LEAF_TAG: &[u8] = b"radix/leaf/v1";
const MAX_STATEMENT_BYTES: usize = 4096;
const MAX_OUTPUT_BYTES: usize = 2048;
// Stable byte offsets relative to the canonical statement frame (excluding the
// separate public-root prefix). Fixed-size output fields precede ciphertext.
pub(crate) const STATEMENT_FEE_BYTES_OFFSET: usize = 157;
pub(crate) const STATEMENT_NULLIFIER_BYTES_OFFSET: usize = 175;
pub(crate) const STATEMENT_OUTPUT_COMMITMENT_BYTES_OFFSET: usize = 278;
const FRAME_FIELD_LENGTH_PREFIX_BYTES: usize = 4;
pub(crate) const STATEMENT_OUTPUT_KEM_CIPHERTEXT_BYTES_OFFSET: usize =
    STATEMENT_OUTPUT_COMMITMENT_BYTES_OFFSET + 64 + FRAME_FIELD_LENGTH_PREFIX_BYTES;
pub(crate) const STATEMENT_OUTPUT_NONCE_BYTES_OFFSET: usize =
    STATEMENT_OUTPUT_KEM_CIPHERTEXT_BYTES_OFFSET + 1088 + FRAME_FIELD_LENGTH_PREFIX_BYTES;
pub(crate) const STATEMENT_OUTPUT_CIPHERTEXT_LENGTH_PREFIX_OFFSET: usize =
    STATEMENT_OUTPUT_NONCE_BYTES_OFFSET + 12;
pub(crate) const STATEMENT_OUTPUT_CIPHERTEXT_BYTES_OFFSET: usize =
    STATEMENT_OUTPUT_CIPHERTEXT_LENGTH_PREFIX_OFFSET + FRAME_FIELD_LENGTH_PREFIX_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputRecordV1 {
    pub commitment: [u8; 64],
    pub kem_ciphertext: [u8; 1088],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub leaf: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionStatementV1 {
    pub chain_id: [u8; 32],
    pub anchor_height: u64,
    pub root_out: [u8; 64],
    pub fee: u64,
    pub nullifier: [u8; 64],
    pub output: OutputRecordV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementCodecError {
    Malformed(&'static str),
}

impl fmt::Display for StatementCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => {
                write!(formatter, "malformed transaction statement: {reason}")
            }
        }
    }
}

impl Error for StatementCodecError {}

type Result<T> = std::result::Result<T, StatementCodecError>;

impl TransactionStatementV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_STATEMENT_BYTES {
            return Err(StatementCodecError::Malformed(
                "statement exceeds size limit",
            ));
        }
        let fields = parse_frame(
            bytes,
            STATEMENT_TAG,
            &[
                (32, 32),
                (2, 2),
                (8, 8),
                (64, 64),
                (8, 8),
                (6, 70),
                (6, MAX_OUTPUT_BYTES + 6),
            ],
        )?;
        if fields[1] != 1u16.to_le_bytes() {
            return Err(StatementCodecError::Malformed(
                "unsupported statement version",
            ));
        }
        let anchor_height = u64::from_le_bytes(fields[2].try_into().unwrap());
        let fee = u64::from_le_bytes(fields[4].try_into().unwrap());
        let nullifier_bytes = parse_single_vec(fields[5], 64)?;
        if nullifier_bytes.len() != 64 {
            return Err(StatementCodecError::Malformed("nullifier must be 64 bytes"));
        }
        let output_bytes = parse_single_vec(fields[6], MAX_OUTPUT_BYTES)?;
        let output = parse_output(output_bytes)?;
        let statement = Self {
            chain_id: fields[0].try_into().unwrap(),
            anchor_height,
            root_out: fields[3].try_into().unwrap(),
            fee,
            nullifier: nullifier_bytes.try_into().unwrap(),
            output,
        };
        if statement.serialize()?.as_slice() != bytes {
            return Err(StatementCodecError::Malformed(
                "noncanonical statement encoding",
            ));
        }
        Ok(statement)
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        if !(156..=668).contains(&self.output.ciphertext.len()) {
            return Err(StatementCodecError::Malformed(
                "ciphertext length outside 156..=668",
            ));
        }
        if output_leaf(
            self.output.commitment,
            self.output.kem_ciphertext,
            self.output.nonce,
            &self.output.ciphertext,
        ) != self.output.leaf
        {
            return Err(StatementCodecError::Malformed(
                "output leaf does not match fields",
            ));
        }
        let output_frame = encode_frame(
            OUTPUT_TAG,
            &[
                self.output.commitment.as_slice(),
                self.output.kem_ciphertext.as_slice(),
                self.output.nonce.as_slice(),
                self.output.ciphertext.as_slice(),
                self.output.leaf.as_slice(),
            ],
        )?;
        if output_frame.len() > MAX_OUTPUT_BYTES {
            return Err(StatementCodecError::Malformed(
                "output record exceeds size limit",
            ));
        }
        let nullifier_vec = encode_single_vec(&self.nullifier)?;
        let output_vec = encode_single_vec(&output_frame)?;
        let statement_bytes = encode_frame(
            STATEMENT_TAG,
            &[
                &self.chain_id,
                &1u16.to_le_bytes(),
                &self.anchor_height.to_le_bytes(),
                &self.root_out,
                &self.fee.to_le_bytes(),
                &nullifier_vec,
                &output_vec,
            ],
        )?;
        if statement_bytes.len() > MAX_STATEMENT_BYTES {
            return Err(StatementCodecError::Malformed(
                "statement exceeds size limit",
            ));
        }
        Ok(statement_bytes)
    }
}

fn parse_output(bytes: &[u8]) -> Result<OutputRecordV1> {
    let fields = parse_frame(
        bytes,
        OUTPUT_TAG,
        &[(64, 64), (1088, 1088), (12, 12), (156, 668), (64, 64)],
    )?;
    let output = OutputRecordV1 {
        commitment: fields[0].try_into().unwrap(),
        kem_ciphertext: fields[1].try_into().unwrap(),
        nonce: fields[2].try_into().unwrap(),
        ciphertext: fields[3].to_vec(),
        leaf: fields[4].try_into().unwrap(),
    };
    if output_leaf(
        output.commitment,
        output.kem_ciphertext,
        output.nonce,
        &output.ciphertext,
    ) != output.leaf
    {
        return Err(StatementCodecError::Malformed(
            "output leaf does not match fields",
        ));
    }
    Ok(output)
}

pub(crate) fn output_leaf(
    commitment: [u8; 64],
    kem_ciphertext: [u8; 1088],
    nonce: [u8; 12],
    ciphertext: &[u8],
) -> [u8; 64] {
    let frame = output_leaf_frame(commitment, kem_ciphertext, nonce, ciphertext);
    output_leaf_from_frame(&frame)
}

pub(crate) fn output_leaf_from_frame(frame: &[u8]) -> [u8; 64] {
    let mut shake = Shake::v256();
    shake.update(frame);
    let mut digest = [0u8; 64];
    shake.finalize(&mut digest);
    digest
}

pub(crate) fn output_leaf_frame(
    commitment: [u8; 64],
    kem_ciphertext: [u8; 1088],
    nonce: [u8; 12],
    ciphertext: &[u8],
) -> Vec<u8> {
    encode_frame(
        LEAF_TAG,
        &[&commitment, &kem_ciphertext, &nonce, ciphertext],
    )
    .expect("fixed-width leaf frame fits in U32")
}

pub(crate) fn output_leaf_absorb_blocks(
    commitment: [u8; 64],
    kem_ciphertext: [u8; 1088],
    nonce: [u8; 12],
    ciphertext: &[u8],
) -> Vec<[u8; 136]> {
    let frame = output_leaf_frame(commitment, kem_ciphertext, nonce, ciphertext);
    output_leaf_absorb_blocks_from_frame(&frame)
}

pub(crate) fn output_leaf_absorb_blocks_from_frame(frame: &[u8]) -> Vec<[u8; 136]> {
    const RATE: usize = 136;
    let block_count = (frame.len() + 1 + RATE - 1) / RATE;
    (0..block_count)
        .map(|block_index| {
            core::array::from_fn(|offset| {
                let frame_offset = block_index * RATE + offset;
                if frame_offset < frame.len() {
                    frame[frame_offset]
                } else {
                    let mut padding = 0;
                    if frame_offset == frame.len() {
                        padding |= 0x1f;
                    }
                    if offset == RATE - 1 {
                        padding |= 0x80;
                    }
                    padding
                }
            })
        })
        .collect()
}

fn parse_frame<'a>(
    bytes: &'a [u8],
    tag: &[u8],
    schema: &[(usize, usize)],
) -> Result<Vec<&'a [u8]>> {
    let header_len = FRAME_MAGIC.len() + 1 + 2 + tag.len() + 2;
    if bytes.len() < header_len || &bytes[..5] != FRAME_MAGIC {
        return Err(StatementCodecError::Malformed(
            "bad frame magic or truncated header",
        ));
    }
    if bytes[5] != FRAME_VERSION {
        return Err(StatementCodecError::Malformed("unsupported frame version"));
    }
    let mut offset = 6;
    if read_u16(bytes, &mut offset)? as usize != tag.len() {
        return Err(StatementCodecError::Malformed("wrong tag length"));
    }
    let tag_end = offset + tag.len();
    if bytes.get(offset..tag_end) != Some(tag) {
        return Err(StatementCodecError::Malformed("wrong frame tag"));
    }
    offset = tag_end;
    if read_u16(bytes, &mut offset)? as usize != schema.len() {
        return Err(StatementCodecError::Malformed("wrong field count"));
    }
    let mut fields = Vec::with_capacity(schema.len());
    for (minimum, maximum) in schema {
        let length = read_u32(bytes, &mut offset)? as usize;
        if length < *minimum || length > *maximum {
            return Err(StatementCodecError::Malformed(
                "field length outside bounds",
            ));
        }
        let end = offset
            .checked_add(length)
            .ok_or(StatementCodecError::Malformed("field length overflow"))?;
        let field = bytes
            .get(offset..end)
            .ok_or(StatementCodecError::Malformed("truncated field"))?;
        fields.push(field);
        offset = end;
    }
    if offset != bytes.len() {
        return Err(StatementCodecError::Malformed("trailing frame bytes"));
    }
    Ok(fields)
}

fn parse_single_vec(bytes: &[u8], max_item_len: usize) -> Result<&[u8]> {
    if bytes.len() < 6 || read_u16(bytes, &mut 0usize)? != 1 {
        return Err(StatementCodecError::Malformed(
            "expected exactly one vector item",
        ));
    }
    let mut offset = 2;
    let length = read_u32(bytes, &mut offset)? as usize;
    if length > max_item_len || offset.checked_add(length) != Some(bytes.len()) {
        return Err(StatementCodecError::Malformed("invalid vector item length"));
    }
    Ok(&bytes[offset..])
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or(StatementCodecError::Malformed("offset overflow"))?;
    let value = u16::from_le_bytes(
        bytes
            .get(*offset..end)
            .ok_or(StatementCodecError::Malformed("truncated U16"))?
            .try_into()
            .unwrap(),
    );
    *offset = end;
    Ok(value)
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or(StatementCodecError::Malformed("offset overflow"))?;
    let value = u32::from_le_bytes(
        bytes
            .get(*offset..end)
            .ok_or(StatementCodecError::Malformed("truncated U32"))?
            .try_into()
            .unwrap(),
    );
    *offset = end;
    Ok(value)
}

fn encode_single_vec(item: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(item.len())
        .map_err(|_| StatementCodecError::Malformed("vector item too long"))?;
    let mut bytes = Vec::with_capacity(6 + item.len());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(item);
    Ok(bytes)
}

fn encode_frame(tag: &[u8], fields: &[&[u8]]) -> Result<Vec<u8>> {
    let tag_len =
        u16::try_from(tag.len()).map_err(|_| StatementCodecError::Malformed("tag too long"))?;
    let count = u16::try_from(fields.len())
        .map_err(|_| StatementCodecError::Malformed("too many fields"))?;
    let capacity = 5usize
        .checked_add(1 + 2 + tag.len() + 2)
        .and_then(|size| {
            fields
                .iter()
                .try_fold(size, |sum, field| sum.checked_add(4 + field.len()))
        })
        .ok_or(StatementCodecError::Malformed("frame size overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(FRAME_MAGIC);
    bytes.push(FRAME_VERSION);
    bytes.extend_from_slice(&tag_len.to_le_bytes());
    bytes.extend_from_slice(tag);
    bytes.extend_from_slice(&count.to_le_bytes());
    for field in fields {
        let length = u32::try_from(field.len())
            .map_err(|_| StatementCodecError::Malformed("field too long"))?;
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_array<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), 2 * N);
        core::array::from_fn(|index| {
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()
        })
    }

    fn sample() -> TransactionStatementV1 {
        let commitment = [b'o'; 64];
        let kem_ciphertext = [b'k'; 1088];
        let nonce = [b'n'; 12];
        let ciphertext = vec![b'c'; 156];
        let leaf = output_leaf(commitment, kem_ciphertext, nonce, &ciphertext);
        TransactionStatementV1 {
            chain_id: [b'x'; 32],
            anchor_height: 12,
            root_out: [b'r'; 64],
            fee: 1,
            nullifier: [b'z'; 64],
            output: OutputRecordV1 {
                commitment,
                kem_ciphertext,
                nonce,
                ciphertext,
                leaf,
            },
        }
    }

    #[test]
    fn output_field_offsets_match_canonical_statement_encoding() {
        for ciphertext_len in [156, 412, 668] {
            let mut statement = sample();
            statement.output.ciphertext = vec![b'c'; ciphertext_len];
            statement.output.leaf = output_leaf(
                statement.output.commitment,
                statement.output.kem_ciphertext,
                statement.output.nonce,
                &statement.output.ciphertext,
            );
            let bytes = statement.serialize().unwrap();
            assert_eq!(
                &bytes[STATEMENT_OUTPUT_COMMITMENT_BYTES_OFFSET
                    ..STATEMENT_OUTPUT_COMMITMENT_BYTES_OFFSET + 64],
                statement.output.commitment.as_slice(),
            );
            assert_eq!(
                &bytes[STATEMENT_OUTPUT_KEM_CIPHERTEXT_BYTES_OFFSET
                    ..STATEMENT_OUTPUT_KEM_CIPHERTEXT_BYTES_OFFSET + 1088],
                statement.output.kem_ciphertext.as_slice(),
            );
            assert_eq!(
                &bytes
                    [STATEMENT_OUTPUT_NONCE_BYTES_OFFSET..STATEMENT_OUTPUT_NONCE_BYTES_OFFSET + 12],
                statement.output.nonce.as_slice(),
            );
            assert_eq!(
                u32::from_le_bytes(
                    bytes[STATEMENT_OUTPUT_CIPHERTEXT_LENGTH_PREFIX_OFFSET
                        ..STATEMENT_OUTPUT_CIPHERTEXT_BYTES_OFFSET]
                        .try_into()
                        .unwrap(),
                ) as usize,
                ciphertext_len,
            );
            assert_eq!(
                &bytes[STATEMENT_OUTPUT_CIPHERTEXT_BYTES_OFFSET
                    ..STATEMENT_OUTPUT_CIPHERTEXT_BYTES_OFFSET + ciphertext_len],
                statement.output.ciphertext.as_slice(),
            );
        }
    }

    #[test]
    fn output_leaf_matches_python_shake_frame_vector() {
        assert_eq!(
            sample().output.leaf,
            hex_array::<64>(
                "7b945ae5bd9e5cb7462849cf9b73c0b4e71f7f6c9c6f10c251de32e8c0939e3c184c2a1ac5686cb93e2f44295a6d191a84547eaae1c588317e4a6d28449fabba"
            )
        );
    }

    #[test]
    fn output_leaf_frame_layout_is_exact_and_block_boundary_known() {
        let output = sample().output;
        let frame = output_leaf_frame(
            output.commitment,
            output.kem_ciphertext,
            output.nonce,
            &output.ciphertext,
        );
        assert_eq!(frame.len(), 1359);
        assert_eq!(&frame[..23], b"RADIX\x01\r\0radix/leaf/v1\x04\0");
        assert_eq!(&frame[23..27], &64u32.to_le_bytes());
        assert_eq!(&frame[91..95], &1088u32.to_le_bytes());
        assert_eq!(&frame[1183..1187], &12u32.to_le_bytes());
        assert_eq!(&frame[1199..1203], &156u32.to_le_bytes());
        assert_eq!(frame[1358], b'c');
        // The 1,359-byte frame ends at rate-byte 135, so SHAKE's 0x1f and
        // 0x80 padding bits occupy that same byte (0x9f).
        assert_eq!(frame.len() % 136, 135);
    }

    #[test]
    fn output_leaf_absorption_blocks_cover_padding_boundaries() {
        let base = sample().output;
        for (ciphertext_len, expected_blocks, pad_at, pad_byte) in [
            (156, 10, 135, 0x9f),
            (157, 11, 0, 0x1f),
            (668, 14, 103, 0x1f),
        ] {
            let ciphertext = vec![b'c'; ciphertext_len];
            let blocks = output_leaf_absorb_blocks(
                base.commitment,
                base.kem_ciphertext,
                base.nonce,
                &ciphertext,
            );
            let frame = output_leaf_frame(
                base.commitment,
                base.kem_ciphertext,
                base.nonce,
                &ciphertext,
            );
            assert_eq!(blocks.len(), expected_blocks);
            let mut framed = Vec::with_capacity(blocks.len() * 136);
            for block in &blocks {
                framed.extend_from_slice(block);
            }
            assert_eq!(&framed[..frame.len()], frame.as_slice());
            assert_eq!(blocks.last().unwrap()[pad_at], pad_byte);
            assert_eq!(
                blocks.last().unwrap()[135],
                0x80 | if pad_at == 135 { 0x1f } else { 0 }
            );
        }
    }

    #[test]
    fn output_leaf_absorb_blocks_are_correct_for_every_allowed_ciphertext_length() {
        let base = sample().output;
        for ciphertext_len in 156..=668 {
            let ciphertext = vec![b'c'; ciphertext_len];
            let frame = output_leaf_frame(
                base.commitment,
                base.kem_ciphertext,
                base.nonce,
                &ciphertext,
            );
            let blocks = output_leaf_absorb_blocks(
                base.commitment,
                base.kem_ciphertext,
                base.nonce,
                &ciphertext,
            );
            assert_eq!(blocks.len(), (frame.len() + 136) / 136);
            let padded: Vec<u8> = blocks.iter().flatten().copied().collect();
            assert_eq!(&padded[..frame.len()], frame.as_slice());
            for offset in frame.len()..padded.len() {
                let mut expected = if offset == frame.len() { 0x1f } else { 0 };
                if offset % 136 == 135 {
                    expected |= 0x80;
                }
                assert_eq!(
                    padded[offset], expected,
                    "ciphertext length {ciphertext_len}, offset {offset}"
                );
            }
        }
    }

    #[test]
    fn strict_one_by_one_statement_roundtrip_and_mutation_rejection() {
        let statement = sample();
        let bytes = statement.serialize().unwrap();
        let parsed = TransactionStatementV1::parse(&bytes).unwrap();
        assert_eq!(bytes.len(), 1678); // Python radix_core.wire.serialize() vector.
        assert_eq!(
            &bytes[..48],
            &hex_array::<48>(
                "524144495801150072616469782f74782d73746174656d656e742f763107002000000078787878787878787878787878"
            )
        );
        assert_eq!(parsed, statement);
        assert_eq!(parsed.serialize().unwrap(), bytes);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(TransactionStatementV1::parse(&trailing).is_err());
        let mut version = bytes.clone();
        version[5] ^= 1;
        assert!(TransactionStatementV1::parse(&version).is_err());
        let mut wrong_leaf = bytes.clone();
        *wrong_leaf.last_mut().unwrap() ^= 1;
        assert!(TransactionStatementV1::parse(&wrong_leaf).is_err());
    }

    #[test]
    fn balance_public_field_offsets_are_stable_for_ciphertext_extremes() {
        for ciphertext_len in [156, 668] {
            let mut statement = sample();
            statement.fee = 0x8877_6655_4433_2211;
            statement.output.ciphertext = vec![b'c'; ciphertext_len];
            statement.output.leaf = output_leaf(
                statement.output.commitment,
                statement.output.kem_ciphertext,
                statement.output.nonce,
                &statement.output.ciphertext,
            );
            let bytes = statement.serialize().unwrap();
            assert_eq!(
                &bytes[STATEMENT_FEE_BYTES_OFFSET..STATEMENT_FEE_BYTES_OFFSET + 8],
                &statement.fee.to_le_bytes()
            );
            assert_eq!(
                &bytes[STATEMENT_OUTPUT_COMMITMENT_BYTES_OFFSET
                    ..STATEMENT_OUTPUT_COMMITMENT_BYTES_OFFSET + 64],
                &statement.output.commitment
            );
        }
    }

    #[test]
    fn maximum_output_ciphertext_is_bounded_and_roundtrips() {
        let mut maximum = sample();
        maximum.output.ciphertext = vec![b'c'; 668];
        maximum.output.leaf = output_leaf(
            maximum.output.commitment,
            maximum.output.kem_ciphertext,
            maximum.output.nonce,
            &maximum.output.ciphertext,
        );
        let bytes = maximum.serialize().unwrap();
        assert!(bytes.len() <= MAX_STATEMENT_BYTES);
        assert_eq!(TransactionStatementV1::parse(&bytes).unwrap(), maximum);

        let mut oversized = maximum.clone();
        oversized.output.ciphertext.push(b'c');
        oversized.output.leaf = output_leaf(
            oversized.output.commitment,
            oversized.output.kem_ciphertext,
            oversized.output.nonce,
            &oversized.output.ciphertext,
        );
        assert!(oversized.serialize().is_err());

        // Rebuild a well-framed raw statement to ensure the parser independently
        // rejects a valid leaf hash over a ciphertext that exceeds the profile cap.
        let output_frame = encode_frame(
            OUTPUT_TAG,
            &[
                &oversized.output.commitment,
                &oversized.output.kem_ciphertext,
                &oversized.output.nonce,
                &oversized.output.ciphertext,
                &oversized.output.leaf,
            ],
        )
        .unwrap();
        let nullifier_vec = encode_single_vec(&oversized.nullifier).unwrap();
        let output_vec = encode_single_vec(&output_frame).unwrap();
        let version = 1u16.to_le_bytes();
        let height = oversized.anchor_height.to_le_bytes();
        let fee = oversized.fee.to_le_bytes();
        let raw_oversized = encode_frame(
            STATEMENT_TAG,
            &[
                &oversized.chain_id,
                &version,
                &height,
                &oversized.root_out,
                &fee,
                &nullifier_vec,
                &output_vec,
            ],
        )
        .unwrap();
        assert!(raw_oversized.len() <= MAX_STATEMENT_BYTES);
        assert!(TransactionStatementV1::parse(&raw_oversized).is_err());
    }

    #[test]
    fn rejects_other_arities_and_oversized_statement() {
        let mut bytes = sample().serialize().unwrap();
        let nf_vec_count =
            5 + 1 + 2 + STATEMENT_TAG.len() + 2 + 4 + 32 + 4 + 2 + 4 + 8 + 4 + 64 + 4 + 8 + 4;
        // The first byte of the single-nullifier vector count is at this fixed canonical offset.
        bytes[nf_vec_count] = 2;
        assert!(TransactionStatementV1::parse(&bytes).is_err());
        assert!(TransactionStatementV1::parse(&vec![0; MAX_STATEMENT_BYTES + 1]).is_err());
    }
}
